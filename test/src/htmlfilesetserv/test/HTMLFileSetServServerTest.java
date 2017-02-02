package htmlfilesetserv.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.IOUtils;
import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import htmlfilesetserv.HTMLFileSetHTTPServer;
import us.kbase.auth.AuthToken;
import us.kbase.abstracthandle.AbstractHandleClient;
import us.kbase.abstracthandle.Handle;
import us.kbase.auth.AuthService;
import us.kbase.common.service.JsonClientException;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.Tuple9;
import us.kbase.common.service.UObject;
import us.kbase.common.test.TestCommon;
import us.kbase.common.test.TestException;
import us.kbase.shock.client.BasicShockClient;
import us.kbase.shock.client.ShockNode;
import us.kbase.shock.client.exceptions.ShockNoNodeException;
import us.kbase.workspace.CreateWorkspaceParams;
import us.kbase.workspace.ObjectIdentity;
import us.kbase.workspace.ObjectSaveData;
import us.kbase.workspace.SaveObjectsParams;
import us.kbase.workspace.SetGlobalPermissionsParams;
import us.kbase.workspace.SetPermissionsParams;
import us.kbase.workspace.WorkspaceClient;
import us.kbase.workspace.WorkspaceIdentity;

public class HTMLFileSetServServerTest {
	
	private static AuthToken TOKEN1;
	private static String TOKEN1_MUNGED;
	private static AuthToken TOKEN2;
	private static Map<String, String> CONFIG = null;
	
	private static Path SCRATCH;
	private static HTMLFileSetHTTPServer HTML_SERVER;
	private static Tuple9<Long, String, String, String, Long, String, String,
			String, Map<String, String>> WS_READ;
	private static Tuple9<Long, String, String, String, Long, String, String,
			String, Map<String, String>> WS_PRIV;
	
	private static WorkspaceClient WS1;
	private static WorkspaceClient WS2;
	
	private static URL SHOCK_URL;
	private static URL HANDLE_URL;
	
	private static AbstractHandleClient HANDLE;
	
	private static URL HTTP_ENDPOINT;
	
	private static final UUID TEST_UUID = UUID.randomUUID();
	private static final String TEST_BAD_UUID = TEST_UUID + "A";
	
	private static final Map<String, NodeAndHandle> CREATED_NODES = new HashMap<>();
	
	private static final Map<String, List<ShockNode>> OBJ_TO_NODES = new HashMap<>();
	
	private static final Path PATH_TO_TEST_ZIP_WITH_DIRS = Paths.get(
			"./test/src/htmlfilesetserv/test/zipWithDirectories.zip").toAbsolutePath();
	
	@BeforeClass
	public static void init() throws Exception {
		
		String configFilePath = System.getenv("KB_DEPLOYMENT_CONFIG");
		File deploy = new File(configFilePath);
		Ini ini = new Ini(deploy);
		CONFIG = ini.get("HTMLFileSetServ");
		SCRATCH = Paths.get(CONFIG.get("scratch"));
		Path testCfg = SCRATCH.resolve("../test.cfg");
		Properties p = new Properties();
		p.load(Files.newInputStream(testCfg));

		//TODO TEST AUTH make configurable?
		TOKEN1 = AuthService.validateToken(System.getenv("KB_AUTH_TOKEN"));
		final String t2 = p.getProperty("test_user2_token");
		if (t2 == null || t2.trim().isEmpty()) {
			throw new TestException(
					"test property test_user2_token not supplied");
		}
		TOKEN1_MUNGED = mungeTokenPerShane(TOKEN1);
		
		//TODO TEST AUTH make configurable?
		TOKEN2 = AuthService.validateToken(t2);
		if (TOKEN1.getUserName().equals(TOKEN2.getUserName())) {
			throw new TestException(String.format(
					"The two users specified in the test config " +
					"must be different users: %s %s",
					TOKEN1.getUserName(), TOKEN2.getUserName()));
		}
		
		// These lines are necessary because we don't want to start linux
		// syslog bridge service
		JsonServerSyslog.setStaticUseSyslog(false);
		JsonServerSyslog.setStaticMlogFile(
				new File(CONFIG.get("scratch"), "test.log").getAbsolutePath());
		
		final String wsURL = CONFIG.get("workspace-url");
		WS1 = new WorkspaceClient(new URL(wsURL), TOKEN1);
		WS2 = new WorkspaceClient(new URL(wsURL), TOKEN2);
		
		SHOCK_URL = new URL(CONFIG.get("shock-url"));
		HANDLE_URL = new URL(CONFIG.get("handle-service-url"));
		
		HANDLE = new AbstractHandleClient(
				HANDLE_URL, TOKEN1);
		
		long suffix = System.currentTimeMillis();
		final String wsName1 = "test_HTMLFileSetServ_" + suffix;
		WS_READ = WS1.createWorkspace(new CreateWorkspaceParams()
				.withWorkspace(wsName1));
		System.out.println("Created test workspace " + WS_READ.getE2());
		WS_PRIV = WS2.createWorkspace(new CreateWorkspaceParams()
				.withWorkspace(wsName1 + "private"));
		System.out.println("Created test workspace " + WS_PRIV.getE2());
		WS1.setPermissions(new SetPermissionsParams().withId(WS_READ.getE1())
				.withNewPermission("w")
				.withUsers(Arrays.asList(TOKEN2.getUserName())));
		HTML_SERVER = startupHTMLServer(wsURL);
		final int htmlport = HTML_SERVER.getServerPort();
		HTTP_ENDPOINT = new URL("http://localhost:" + htmlport + "/api/v1");
		System.out.println("Started html server on port " + htmlport);
		
		//makes httpurlconnection handle cookies correctly
		final CookieManager cookieManager = new CookieManager();
		CookieHandler.setDefault(cookieManager);
		
		loadTestData();
	}
	
	private static String mungeTokenPerShane(final AuthToken token)
			throws UnsupportedEncodingException {
		final Map<String, String> contents = new HashMap<>();
		contents.put("token", token.getToken());
		contents.put("un", token.getUserName());
		contents.put("user_id", token.getToken());
		// don't really need this, but whatever
		contents.put("kbase_sessionid", UUID.randomUUID().toString());
		return buildMungedCookie(contents);
	}
	
	private static String buildMungedCookie(
			final Map<String, String> contents)
			throws UnsupportedEncodingException {
		final List<String> parts = new LinkedList<>();
		for (final Entry<String, String> e: contents.entrySet()) {
			parts.add(e.getKey() + "=" + e.getValue().replace("|", "PIPESIGN")
					.replace("=", "EQUALSSIGN"));
		}
		final String unenc = String.join("|", parts);
		return URLEncoder.encode(unenc, StandardCharsets.UTF_8.name());
	}

	private static HTMLFileSetHTTPServer startupHTMLServer(
			final String wsURL)
			throws Exception {
		
		//write the server config file:
		File iniFile = File.createTempFile("test", ".cfg",
				new File(SCRATCH.toString()));
		if (iniFile.exists()) {
			iniFile.delete();
		}
		System.out.println("Created HTML serv temporary config file: " +
				iniFile.getAbsolutePath());
		Ini ini = new Ini();
		Section html = ini.add("HTMLFileSetServ");
		html.add("workspace-url", wsURL);
		html.add("scratch", SCRATCH);
		//TODO TEST AUTH make auth url configurable
		html.add("auth-service-url",
				"https://ci.kbase.us/services/authorization");
		ini.store(iniFile);
		iniFile.deleteOnExit();

		//set up env
		Map<String, String> env = TestCommon.getenv();
		env.put("KB_DEPLOYMENT_CONFIG", iniFile.getAbsolutePath());

		HTMLFileSetHTTPServer server = new HTMLFileSetHTTPServer();
		new HTMLServerThread(server).start();
		System.out.println("Main thread waiting for html server to start up");
		while (server.getServerPort() == null) {
			Thread.sleep(1000);
		}
		return server;
	}

	protected static class HTMLServerThread extends Thread {
		private HTMLFileSetHTTPServer server;
		
		protected HTMLServerThread(HTMLFileSetHTTPServer server) {
			this.server = server;
		}
		
		public void run() {
			try {
				server.startupServer();
			} catch (Exception e) {
				System.err.println("Can't start server:");
				e.printStackTrace();
			}
		}
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		final List<String> handlesToDelete = new LinkedList<>();
		for (final Entry<String, NodeAndHandle> e: CREATED_NODES.entrySet()) {
			try {
				e.getValue().node.delete();
			} catch (ShockNoNodeException nne) {
				//continue
			}
			handlesToDelete.add(e.getValue().handleID);
		}
		HANDLE.deleteHandles(HANDLE.hidsToHandles(handlesToDelete));
		if (HTML_SERVER != null) {
			System.out.print("Killing html server ... ");
			HTML_SERVER.stopServer();
			System.out.println("Done");
		}
		if (WS_READ != null) {
			System.out.println("Removing readable test workspace");
			WS1.deleteWorkspace(new WorkspaceIdentity()
					.withId(WS_READ.getE1()));
		}
		if (WS_PRIV != null) {
			System.out.println("Removing private test workspace");
			WS2.deleteWorkspace(new WorkspaceIdentity()
					.withId(WS_PRIV.getE1()));
			
		}
	}
	
	private static void loadTestData() throws Exception {
		// workspace for user 1
		saveHTMLFileSet(WS1, WS_READ.getE1(), "html", "file1", "file.txt");
		saveHTMLFileSet(WS1, WS_READ.getE1(), "html", "file2", "file.txt");
		saveHTMLFileSet(WS1, WS_READ.getE1(), "cache", "cachefile",
				"file.txt");
		saveHTMLFileSet(WS1, WS_READ.getE1(), "index", "indexfile",
				"index.html");
		saveEncodedZipFileToHTMLFileSet(WS1, WS_READ.getE1(), "nullenc", null);
		saveEncodedZipFileToHTMLFileSet(WS1, WS_READ.getE1(), "noenc", "");
		saveEncodedZipFileToHTMLFileSet(WS1, WS_READ.getE1(), "badenc",
				"bad*base64chars");
		saveEncodedZipFileToHTMLFileSet(WS1, WS_READ.getE1(), "badzip",
				Base64.getEncoder().encodeToString(
						"thisisnotazipfile".getBytes()));
		saveEmptyType(WS1, WS_READ.getE1(), "badtype");
		
		// private workspace for user 2
		saveHTMLFileSet(WS2, WS_PRIV.getE1(), "html", "priv1", "file.txt");
		saveRef(WS2, WS_PRIV.getE1(), "ref", WS_PRIV.getE1(), "html", 1);
		saveRef(WS2, WS_READ.getE1(), "directRef", WS_PRIV.getE1(), "html", 1);
		saveRef(WS2, WS_READ.getE1(), "indirectRef",
				WS_PRIV.getE1(), "ref", 1);
		
		// KBaseReport.Report testing
		final BasicShockClient bsc = new BasicShockClient(SHOCK_URL, TOKEN1);
		
		final ShockNode emptynode = bsc.addNode();
		final String emptyhandle = makeHandle(emptynode);
		CREATED_NODES.put(emptynode.getId().getId(),
				new NodeAndHandle(emptynode, emptyhandle));
		
		final ShockNode delnode = bsc.addNode();
		final String delhandle = makeHandle(delnode);
		CREATED_NODES.put(delnode.getId().getId(),
				new NodeAndHandle(delnode, delhandle));
		
		final ShockNode badzipnode = bsc.addNode(new ByteArrayInputStream(
				"This is not a zip file".getBytes()), "bad.zip", "zip");
		final String badziphandle = makeHandle(badzipnode);
		CREATED_NODES.put(badzipnode.getId().getId(),
				new NodeAndHandle(badzipnode, badziphandle));
		
		
		final byte[] zip1 = makeZipFile("shock1", "shock1.txt");
		final ShockNode node1 = bsc.addNode(new ByteArrayInputStream(zip1), "shock1.zip", "zip");
		final String handle1 = makeHandle(node1);
		CREATED_NODES.put(node1.getId().getId(), new NodeAndHandle(node1, handle1));

		
		final byte[] zip2 = makeZipFile("shock2", "shock2.txt");
		final ShockNode node2 = bsc.addNode(new ByteArrayInputStream(zip2),
				"shock2.zip", "zip");
		final String handle2 = makeHandle(node2);
		CREATED_NODES.put(node2.getId().getId(), new NodeAndHandle(node2, handle2));

		final byte[] zipWithDirs = Files.readAllBytes(PATH_TO_TEST_ZIP_WITH_DIRS);
		final ShockNode dirnode = bsc.addNode(new ByteArrayInputStream(zipWithDirs),
				"dirs.zip", "zip");
		final String dirhandle = makeHandle(dirnode);
		CREATED_NODES.put(dirnode.getId().getId(), new NodeAndHandle(dirnode, dirhandle));

		
		saveKBaseReport(WS1, WS_READ.getE1(), "good2",
				Arrays.asList(node1, node2));
		saveKBaseReport(WS1, WS_READ.getE1(), "dirs", Arrays.asList(dirnode));
		saveKBaseReport(WS1, WS_READ.getE1(), "shocknofile2",
				Arrays.asList(node1, emptynode));
		OBJ_TO_NODES.put("shocknofile2", Arrays.asList(node1, emptynode));
		saveKBaseReport(WS1, WS_READ.getE1(), "shockbadzip2",
				Arrays.asList(node1, badzipnode));
		OBJ_TO_NODES.put("shockbadzip2", Arrays.asList(node1, badzipnode));
		saveKBaseReport(WS1, WS_READ.getE1(), "shockdelnode2",
				Arrays.asList(node1, delnode));
		OBJ_TO_NODES.put("shockdelnode2", Arrays.asList(node1, delnode));
		bsc.deleteNode(delnode.getId());
		
		saveHTMLLinkListToKBaseReport(WS1, WS_READ.getE1(), "nolinks", null);
		saveHTMLLinkListToKBaseReport(WS1, WS_READ.getE1(), "emptylinks", new LinkedList<>());
		
		saveShockURLToKBaseReport(WS1, WS_READ.getE1(), "shockbadsplit",
				SHOCK_URL + "/nde/" + TEST_UUID, handle1);
		saveShockURLToKBaseReport(WS1, WS_READ.getE1(), "shocknonode",
				SHOCK_URL + "/node/" + TEST_UUID, handle1);
		saveShockURLToKBaseReport(WS1, WS_READ.getE1(), "shockinvalidnode",
				SHOCK_URL + "/node/" + TEST_BAD_UUID, handle1);
		final String surl = SHOCK_URL.toString();
		saveShockURLToKBaseReport(WS1, WS_READ.getE1(), "shockinvalidurl",
				surl.replace("https", "htps") + "/node/" + TEST_UUID, handle1);
		saveShockURLToKBaseReport(WS1, WS_READ.getE1(), "shockwrongurl",
				surl.substring(0, surl.indexOf("/services/shock-api")) +
				"/node/" + TEST_UUID, handle1);
		
		
		//test bad zip files
		saveHTMLFileSet(WS1, WS_READ.getE1(), "absolutezip", "foo", "/foo");
		saveHTMLFileSet(WS1, WS_READ.getE1(), "escapezip", "foo", "bar/../../foo");
	}
	
	private static void saveShockURLToKBaseReport(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final String url,
			final String handleID)
			throws Exception {
		final List<Map<String, String>> files = new LinkedList<>();
		final Map<String, String> file = new HashMap<>();
		file.put("name", "foo");
		file.put("URL", url);
		file.put("handle", handleID);
		files.add(file);
		saveHTMLLinkListToKBaseReport(ws, wsid, objname, files);
	}

	private static class NodeAndHandle {
		
		public final ShockNode node;
		public final String handleID;
		
		public NodeAndHandle(final ShockNode node, final String handleID) {
			this.node = node;
			this.handleID = handleID;
		}
	}

	private static void saveKBaseReport(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final List<ShockNode> nodes)
			throws Exception {
		final List<Map<String, String>> files = new LinkedList<>();
		for (final ShockNode sn: nodes) {
			final Map<String, String> file = new HashMap<>();
			file.put("name", "foo");
			final String id = sn.getId().getId();
			file.put("URL", SHOCK_URL + "/node/" + id);
			file.put("handle", CREATED_NODES.get(id).handleID);
			files.add(file);
		}
		saveHTMLLinkListToKBaseReport(ws, wsid, objname, files);
		
	}

	private static void saveHTMLLinkListToKBaseReport(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final List<Map<String, String>> files)
			throws IOException, JsonClientException {
		final Map<String, Object> o = new HashMap<>();
		if (files != null) {
			o.put("html_links", files);
		}
		o.put("objects_created", new LinkedList<String>());
		o.put("text_message", "foo");
		ws.saveObjects(new SaveObjectsParams().withId(wsid)
				.withObjects(Arrays.asList(new ObjectSaveData()
						.withData(new UObject(o))
						.withName(objname)
						.withType("KBaseReport.Report-1.2"))
						)
				);
	}

	private static String makeHandle(final ShockNode node)
			throws IOException, JsonClientException {
		return HANDLE.persistHandle(new Handle()
				.withId(node.getId().getId())
				.withType("shock")
				.withUrl(SHOCK_URL.toString()));
	}

	private static void saveRef(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final long refWsid,
			final String refWsname,
			final int refVersion)
			throws IOException, JsonClientException {
		final Map<String, String> data = new HashMap<>();
		data.put("ref", refWsid + "/" + refWsname + "/" + refVersion);
		ws.saveObjects(new SaveObjectsParams().withId(wsid)
				.withObjects(Arrays.asList(new ObjectSaveData()
						.withData(new UObject(data))
						.withName(objname)
						.withType("Empty.ARef-1.0"))
						)
				);
	}

	private static void saveEmptyType(
			final WorkspaceClient ws,
			final long wsid,
			final String objname)
			throws IOException, JsonClientException {
		
		final Map<String, String> data = new HashMap<>();
		data.put("whee", "whoo");
		ws.saveObjects(new SaveObjectsParams().withId(wsid)
				.withObjects(Arrays.asList(new ObjectSaveData()
						.withData(new UObject(data))
						.withName(objname)
						.withType("Empty.AType-1.0"))
						)
				);
	}

	private static void saveHTMLFileSet(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final String contents,
			final String filename)
			throws IOException, JsonClientException {
		final byte[] zipfile = makeZipFile(contents, filename);
		final String enc = Base64.getEncoder()
				.encodeToString(zipfile);
		saveEncodedZipFileToHTMLFileSet(ws, wsid, objname, enc);
	}

	private static byte[] makeZipFile(
			final String contents,
			final String filename)
			throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (final ZipOutputStream zos = new ZipOutputStream(
				baos, StandardCharsets.UTF_8);) {
		
			final ZipEntry ze = new ZipEntry(filename);
			zos.putNextEntry(ze);
			final byte[] b = contents.getBytes(StandardCharsets.UTF_8);
			zos.write(b, 0, b.length);
		}
		return baos.toByteArray();
	}
	
	private static void saveEncodedZipFileToHTMLFileSet(
			final WorkspaceClient ws,
			final long wsid,
			final String objname,
			final String encodedzip)
			throws IOException, JsonClientException {
		final Map<String, Object> obj = new HashMap<>();
		obj.put("file", encodedzip);
		ws.saveObjects(new SaveObjectsParams().withId(wsid)
				.withObjects(Arrays.asList(new ObjectSaveData()
						.withData(new UObject(obj))
						.withName(objname)
						.withType("HTMLFileSetUtils.HTMLFileSet-0.1"))
						)
				);
	}

	@Test
	public void testSuccessIDsLatestVerCookie() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/1/-/$/file.txt";
		final String absref = WS_READ.getE1() + "/1/2";
		testSuccess(path, absref, TOKEN1_MUNGED, "file2", "cookie");
	}
	
	@Test
	public void testSuccessIDsLatestVerCookieBackup() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/1/-/$/file.txt";
		final String absref = WS_READ.getE1() + "/1/2";
		testSuccess(path, absref, TOKEN1_MUNGED, "file2", "cookiebackup");
	}
	
	/* could test that when sending both cookies the first one is used, but that seems like a fair
	 * amount of work for a temporary situation, since the tests have been written to only send
	 * one cookie. If (god forbid) the 2 cookie solution is the final solution, then write the
	 * test.
	 */
	
	@Test
	public void testSuccessNamesFirstVerHeader() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/1/$/file.txt";
		final String absref = WS_READ.getE1() + "/1/1";
		testSuccess(path, absref, TOKEN1.getToken(), "file1", "auth");
	}
	
	@Test
	public void testSuccessAnonymous() throws Exception {
		WS2.setGlobalPermission(new SetGlobalPermissionsParams()
				.withId(WS_PRIV.getE1()).withNewPermission("r"));
		final String path = "/" + WS_PRIV.getE2() + "/html/1/$/file.txt";
		final String absref = WS_PRIV.getE1() + "/1/1";
		try {
			testSuccess(path, absref, null, "priv1", null);
		} finally {
			WS2.setGlobalPermission(new SetGlobalPermissionsParams()
					.withId(WS_PRIV.getE1()).withNewPermission("n"));
		}
	}
	
	@Test
	public void testSuccessCache() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/cache/1/$/file.txt";
		final String absref = WS_READ.getE1() + "/2/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "cachefile", "cookie");
		//there's not really any way to easily ensure the code is reading
		//from the cache...
		testSuccess(path, absref, TOKEN1.getToken(), "cachefile", "auth");
	}
	
	@Test
	public void testSuccessIndexDotHtml() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/index/-/$/";
		final String absref = WS_READ.getE1() + "/3/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "indexfile", "index.html",
				"cookie", "text/html");
	}
	
	@Test
	public void testSuccess1Ref() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/directRef/-/" +
				WS_PRIV.getE1() + "/html/1/$/file.txt";
		final String absref = WS_PRIV.getE1() + "/1/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "priv1", "file.txt",
				"cookie");
	}
	
	@Test
	public void testSuccess2Ref() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/indirectRef/1/" +
				WS_PRIV.getE1() + "/ref/1/" +
				WS_PRIV.getE1() + "/html/-/$/file.txt";
		final String absref = WS_PRIV.getE1() + "/1/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "priv1", "file.txt",
				"cookie");
	}
	
	@Test
	public void testSuccessReportIndex1() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/0/shock1.txt";
		final String absref = WS_READ.getE1() + "/11/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "shock1", "0/shock1.txt",
				"cookie");
	}
	
	@Test
	public void testSuccessReportIndex2() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/1/shock2.txt";
		final String absref = WS_READ.getE1() + "/11/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "shock2", "1/shock2.txt",
				"cookie");
	}
	
	@Test
	public void testSuccessReportZipWithDirs1() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/dirs/-/$/0/first.txt";
		final String absref = WS_READ.getE1() + "/12/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "this file is first.txt", "0/first.txt",
				"cookie");
	}
	
	@Test
	public void testSuccessReportZipWithDirs2() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/dirs/-/$/0/second/third.txt";
		final String absref = WS_READ.getE1() + "/12/1";
		testSuccess(path, absref, TOKEN1_MUNGED, "this file is third.txt", "0/second/third.txt",
				"cookie");
	}
	
	@Test
	public void testFailNoRead() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 403, String.format(
				"Object html cannot be accessed: User %s may not " +
				"read workspace %s",
				TOKEN1.getUserName(), WS_PRIV.getE1()), "cookie");
	}
	
	@Test
	public void testFailNoReadCookieBackup() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 403, String.format(
				"Object html cannot be accessed: User %s may not " +
				"read workspace %s",
				TOKEN1.getUserName(), WS_PRIV.getE1()), "cookiebackup");
	}
	
	@Test
	public void testFailBadAuthCookie() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, "whee", 401, "Cannot parse token from cookie: " +
				"Subportion of cookie missing value", "cookie");
	}
	
	@Test
	public void testFailBadAuthHeader() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, "whee", 401, String.format(
				"Login failed! Invalid token",
				TOKEN1.getUserName(), WS_READ.getE1()), "auth");
	}
	
	@Test
	public void testFailNoAuth() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, null, 403, String.format(
				"Object html cannot be accessed: Anonymous users may not " +
				"read workspace %s", WS_READ.getE2()), null);
	}
	
	@Test
	public void testFailAuthNullHeader() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, null, 403, String.format(
				"Object html cannot be accessed: Anonymous users may not " +
				"read workspace %s", WS_READ.getE2()), "auth");
	}

	@Test
	public void testFailAuthNullCookie() throws Exception {
		// just winds up with the string "null" server side
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, null, 401, "Cannot parse token from cookie: " +
				"Subportion of cookie missing value", "cookie");
	}
	
	@Test
	public void testFailAuthEmptyHeader() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, "", 403, String.format(
				"Object html cannot be accessed: Anonymous users may not " +
				"read workspace %s", WS_READ.getE2()), "auth");
	}

	@Test
	public void testFailAuthEmptyCookie() throws Exception {
		// appears that the cookie isn't received at all if the value is empty
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, "", 403, String.format(
				"Object html cannot be accessed: Anonymous users may not " +
				"read workspace %s", WS_READ.getE2()), "cookie");
	}
	
	@Test
	public void testFailAuthCookieBadToken() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final Map<String, String> munge = new HashMap<>();
		munge.put("user_id", TOKEN1.getUserName());
		munge.put("un", TOKEN1.getUserName());
		munge.put("token", "whee");
		testFail(path, buildMungedCookie(munge), 401, "Login failed! Invalid token", "cookie");
	}
	
	@Test
	public void testFailAuthCookieEmptyToken() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final Map<String, String> munge = new HashMap<>();
		munge.put("user_id", TOKEN1.getUserName());
		munge.put("un", TOKEN1.getUserName());
		munge.put("token", "");
		testFail(path, buildMungedCookie(munge), 401, "Cannot parse token " +
				"from cookie: Subportion of cookie missing value", "cookie");
	}
	
	@Test
	public void testFailAuthCookieNoToken() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final Map<String, String> munge = new HashMap<>();
		munge.put("user_id", TOKEN1.getUserName());
		munge.put("un", TOKEN1.getUserName());
		munge.put("tokken", TOKEN1.getToken());
		testFail(path, buildMungedCookie(munge), 401,
				"Cannot parse token from cookie: No token section", "cookie");
	}
	
	@Test
	public void testFailNoSuchVersion() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/3/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, String.format(
				"No object with id 1 (name html) and version 3 exists in " +
				"workspace %s (name %s)", WS_READ.getE1(), WS_READ.getE2()), "cookie");
	}
	
	@Test
	public void testFailNoSuchObjectID() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/1000/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, String.format(
				"No object with id 1000 exists in workspace %s (name %s)",
				WS_READ.getE1(), WS_READ.getE2()), "cookie");
	}
	
	@Test
	public void testFailNoSuchObjectName() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/nope/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, String.format(
				"No object with name nope exists in workspace %s (name %s)",
				WS_READ.getE1(), WS_READ.getE2()), "cookie");
	}
	
	@Test
	public void testFailNoSuchWorkspaceID() throws Exception {
		final String path = "/100000000/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404,
				"Object html cannot be accessed: No workspace with id " +
				"100000000 exists", "cookie");
	}
	
	@Test
	public void testFailNoSuchWorkspaceName() throws Exception {
		final String path = "/ireallyhopethiswsdoesntexist/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404,
				"Object html cannot be accessed: No workspace with name " +
				"ireallyhopethiswsdoesntexist exists", "cookie");
	}
	
	@Test
	public void testFailDeletedObject() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final ObjectIdentity oi = new ObjectIdentity()
				.withWsid(WS_READ.getE1()).withName("html");
		WS1.deleteObjects(Arrays.asList(oi));
		try {
			testFail(path, TOKEN1_MUNGED, 404, String.format(
					"Object 1 (name html) in workspace %s (name %s) has been deleted",
					WS_READ.getE1(), WS_READ.getE2()), "cookie");
		} finally {
			WS1.undeleteObjects(Arrays.asList(oi));
		}
	}
	
	@Test
	public void testFailDeletedWorkspace() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final WorkspaceIdentity wsi = new WorkspaceIdentity()
				.withId(WS_READ.getE1());
		WS1.deleteWorkspace(wsi);
		try {
			testFail(path, TOKEN1_MUNGED, 404, String.format(
					 "Object html cannot be accessed: Workspace %s is deleted",
					WS_READ.getE2()), "cookie");
		} finally {
			WS1.undeleteWorkspace(wsi);
		}
	}
	
	@Test
	public void testFailNoPath() throws Exception {
		testFail("", TOKEN1_MUNGED, 404, "Empty path", "cookie");
	}
	
	@Test
	public void testFailNoVersion() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailNoSeparator() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailNoSlashPostSeparator() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/index/-/$";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailNoFile() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/bar.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailNullEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/nullenc/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Unable to open the zip file",
				"cookie");
	}
	
	@Test
	public void testFailNoEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/noenc/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Unable to open the zip file",
				"cookie");
	}
	
	@Test
	public void testFailBadEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badenc/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Failed to decode the zip " +
				"file from the workspace object contents", "cookie");
	}
	
	@Test
	public void testFailBadZip() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badzip/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Unable to open the zip file",
				"cookie");
	}
	
	@Test
	public void testFailBadType() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badtype/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 400,
				"The type Empty.AType-1.0 cannot be processed by this service",
				"cookie");
	}

	@Test
	public void testFailRef() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/indirectRef/1/" +
				WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 400, String.format(
				"Reference path #1 starting with object indirectRef version 1 in workspace " +
				"%s, position 1: Object indirectRef version 1 in workspace %s does not " +
				"contain a reference to object html in workspace %s",
				WS_READ.getE1(), WS_READ.getE1(), WS_PRIV.getE1()), "cookie");
	}
	
	@Test
	public void testFailRefBadPath() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/directRef/" +
				WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailReportIndexOOB() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/2/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Zip identifier 2 exceeds " +
				"number of zip files in KBaseReport list", "cookie");
	}

	@Test
	public void testFailReportNoSuchFile() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/1/shock1.txt";
		testFail(path, TOKEN1_MUNGED, 404, "Not Found", "cookie");
	}
	
	@Test
	public void testFailReportWsException() throws Exception {
		// most ws exceptions are tested for htmlfileset
		final String path = "/" + WS_READ.getE2() + "/good3/-/$/1/shock1.txt";
		testFail(path, TOKEN1_MUNGED, 404, String.format(
				"No object with name good3 exists in workspace %s (name %s)",
						WS_READ.getE1(), WS_READ.getE2()), "cookie");
	}
	
	@Test
	public void testFailReportIndexString() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/bl/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 400, "The zip identifier section " +
				"of the path must be a non-negative integer", "cookie");
	}
	
	@Test
	public void testFailReportIndexNegInt() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/good2/-/$/-1/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 400, "The zip identifier section " +
				"of the path must be a non-negative integer", "cookie");
	}
	
	@Test
	public void testFailReportIndexNoLinks() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/nolinks/-/$/0/shock1.txt";
		testFail(path, TOKEN1_MUNGED, 404,
				"This KBase report does not contain html links", "cookie");
	}
	
	@Test
	public void testFailReportIndexEmptyLinks() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/emptylinks/-/$/0/shock1.txt";
		testFail(path, TOKEN1_MUNGED, 404,
				"This KBase report does not contain html links", "cookie");
	}
	
	@Test
	public void testFailReportNoShockFile() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shocknofile2/-/$/1/shock2.txt";
		final String node = OBJ_TO_NODES.get("shocknofile2")
				.get(1).getId().getId();
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"The shock node %s has no file", node), "cookie");
	}
	
	@Test
	public void testFailReportBadZipFile() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shockbadzip2/-/$/1/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Unable to open the zip file",
				"cookie");
	}
	
	@Test
	public void testFailReportBadURLSplit() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shockbadsplit/-/$/0/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"Invalid shock node url: %s/nde/%s", SHOCK_URL, TEST_UUID),
				"cookie");
	}
	
	@Test
	public void testFailReportNoShockNode() throws Exception {
		// node id is valid but does not exist, means the url was set
		// incorrectly in the report object but handle is valid
		final String path = "/" + WS_READ.getE2() +
				"/shocknonode/-/$/0/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"No such shock node: %s", TEST_UUID), "cookie");
	}
	
	@Test
	public void testFailReportDeletedShockNode() throws Exception {
		// deleted after saving so workspace calling the handle service to
		// update sharing fails
		final String path = "/" + WS_READ.getE2() +
				"/shockdelnode2/-/$/0/shock2.txt";
		final String shockID = OBJ_TO_NODES.get("shockdelnode2")
				.get(1).getId().getId();
		final String handleID = CREATED_NODES.get(shockID).handleID;
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"Workspace reported a handle error: The Handle Manager " +
				"reported a problem while attempting to set Handle ACLs: " +
				"Unable to set acl(s) on handles %s", handleID), "cookie");
	}
	
	@Test
	public void testFailReportBadShockNodeID() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shockinvalidnode/-/$/0/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"Invalid shock node ID: %s", TEST_BAD_UUID), "cookie");
	}
	
	@Test
	public void testFailReportBadShockURL() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shockinvalidurl/-/$/0/shock2.txt";
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"Invalid shock URL: %s",
				SHOCK_URL.toString().replace("https", "htps")) + "/", "cookie");
	}
	
	@Test
	public void testFailReportWrongShockURL() throws Exception {
		final String path = "/" + WS_READ.getE2() +
				"/shockwrongurl/-/$/0/shock2.txt";
		final String surl = SHOCK_URL.toString();
		testFail(path, TOKEN1_MUNGED, 500, String.format(
				"Invalid shock URL: %s",
				surl.substring(0, surl.indexOf("/services/shock-api"))) + "/",
				"cookie");
	}
	
	@Test
	public void testFailAbsoluteZipFile() throws Exception {
		final String path = "/" + WS_READ.getE1() +
				"/absolutezip/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Zip file contains files outside " +
				"the zip directory - this is a sign of a malicious zip file.",
				"cookie");
	}

	@Test
	public void testFailEscapingZipFile() throws Exception {
		final String path = "/" + WS_READ.getE1() +
				"/escapezip/-/$/file.txt";
		testFail(path, TOKEN1_MUNGED, 500, "Zip file contains files outside " +
				"the zip directory - this is a sign of a malicious zip file.",
				"cookie");
	}
	
	private void testFail(
			final String path,
			final String token,
			final int code,
			String error,
			final String authMode)
			throws Exception {
		logStartTest();
		final URL u = new URL(HTTP_ENDPOINT.toString() + path);
		final HttpURLConnection hc = (HttpURLConnection) u.openConnection();
		setUpAuthHeader(hc, token, authMode);
		hc.setDoInput(true);
		final int gotcode = hc.getResponseCode();
		final String ct = hc.getHeaderField("Content-Type");
		assertThat("incorrect Content-Type", ct, is("text/html"));
		final String contents;
		try (final InputStream is = hc.getErrorStream()) {
			contents = IOUtils.toString(is);
		}
		assertThat("incorrect return code, webpage was:\n" + contents,
				gotcode, is(code));
		error = "Message: " + error + "<br/>";
		assertThat("Error response does not contain " + error +
				", got:\n" + contents,
				contents.contains(error), is(true));
		
		assertNoTempFilesLeftOnDisk();
	}

	private void testSuccess(
			final String path,
			final String absref,
			final String token,
			final String testcontents,
			final String authMode)
			throws Exception {
		testSuccess(path, absref, token, testcontents, "file.txt", authMode);
	}
	
	private void testSuccess(
			final String path,
			final String absref,
			final String token,
			final String testcontents,
			final String filename,
			final String authMode)
			throws Exception {
		testSuccess(path, absref, token, testcontents, filename, authMode, "text/plain");
	}
	
	private void testSuccess(
			final String path,
			final String absref,
			final String token,
			final String testcontents,
			final String filename,
			final String authMode,
			final String contentType)
			throws Exception {
		logStartTest();
		final URL u = new URL(HTTP_ENDPOINT.toString() + path);
		final HttpURLConnection hc = (HttpURLConnection) u.openConnection();
		setUpAuthHeader(hc, token, authMode);
		hc.setDoInput(true);
		int code = hc.getResponseCode();
		if (code != 200) {
			final String contents;
			try (final InputStream is = hc.getErrorStream()) {
				contents = IOUtils.toString(is);
			}
			fail("Request failed. Response code " + code +
					". Page contents:\n" + contents);
		}
		final String ct = hc.getHeaderField("Content-Type");
		assertThat("incorrect Content-Type", ct, is(contentType));
		final String contents;
		try (final InputStream is = hc.getInputStream()) {
			contents = IOUtils.toString(is);
		}
		assertThat("incorrect file contents", contents, is(testcontents));

		final Path filepath = SCRATCH.resolve("cache").resolve(absref)
				.resolve(filename);
		final String cacheContents;
		try (final InputStream is = Files.newInputStream(filepath)) {
			cacheContents = IOUtils.toString(is);
		}
		assertThat("incorrect cache file contents", cacheContents,
				is(testcontents));
		
		assertNoTempFilesLeftOnDisk();
	}

	private void setUpAuthHeader(
			final HttpURLConnection conn,
			final String token,
			final String authMode) {
		if (authMode == null) {
			//do nothing
		} else if (authMode.equals("auth")) {
			conn.setRequestProperty("Authorization", token);
		} else if (authMode.equals("cookie")){
			conn.setRequestProperty("Cookie", "kbase_session=" + token);
		} else if (authMode.equals("cookiebackup")) {
			conn.setRequestProperty("Cookie", "kbase_session_backup=" + token);
		} else {
			throw new IllegalArgumentException("header auth illegal: " + authMode);
		}
	}

	private void logStartTest() {
		final Exception e = new Exception();
		e.fillInStackTrace();
		String method = null;
		for (int i = 1; i < 5; i++) {
			final String mn = e.getStackTrace()[i].getMethodName();
			if (!mn.equals("testFail") && !mn.equals("testSuccess")) {
				method = mn;
				break;
			}
		}
		if (method == null) {
			throw new TestException("Couldn't get test method name");
		}
		System.out.println("\n******************************************\n*");
		System.out.println("* Starting test " + method);
		System.out.println("*\n******************************************");
	}
	
	private void assertNoTempFilesLeftOnDisk() throws IOException {
		final List<Path> tempfiles = new LinkedList<>();
		Files.newDirectoryStream(SCRATCH.resolve("temp")).forEach(p -> tempfiles.add(p));
		for (final Path p: tempfiles) {
			Files.delete(p);
		}
		assertThat("Temp files left on disk", tempfiles, is(new LinkedList<>()));
	}
}
