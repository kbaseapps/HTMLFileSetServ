package htmlfilesetserv.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.URL;
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
import java.util.Properties;
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
import us.kbase.auth.AuthService;
import us.kbase.common.service.JsonClientException;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.Tuple9;
import us.kbase.common.service.UObject;
import us.kbase.common.test.TestCommon;
import us.kbase.common.test.TestException;
import us.kbase.workspace.CreateWorkspaceParams;
import us.kbase.workspace.ObjectIdentity;
import us.kbase.workspace.ObjectSaveData;
import us.kbase.workspace.SaveObjectsParams;
import us.kbase.workspace.SetGlobalPermissionsParams;
import us.kbase.workspace.WorkspaceClient;
import us.kbase.workspace.WorkspaceIdentity;

public class HTMLFileSetServServerTest {
	
	private static AuthToken TOKEN1;
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
	
	private static URL HTTP_ENDPOINT;
	
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
		
		long suffix = System.currentTimeMillis();
		final String wsName1 = "test_HTMLFileSetServ_" + suffix;
		WS_READ = WS1.createWorkspace(new CreateWorkspaceParams()
				.withWorkspace(wsName1));
		WS_PRIV = WS2.createWorkspace(new CreateWorkspaceParams()
				.withWorkspace(wsName1 + "private"));
		HTML_SERVER = startupHTMLServer(wsURL);
		int htmlport = HTML_SERVER.getServerPort();
		HTTP_ENDPOINT = new URL("http://localhost:" + htmlport + "/api/v1");
		System.out.println("Started html server on port " + htmlport);
		
		//makes httpurlconnection handle cookies correctly
		final CookieManager cookieManager = new CookieManager();
		CookieHandler.setDefault(cookieManager);
		
		loadTestData();
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
	
	public static void loadTestData() throws Exception {
		//workspace for user 1
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
		
		//private workspace for user 2
		saveHTMLFileSet(WS2, WS_PRIV.getE1(), "html", "priv1", "file.txt");
		saveRef(WS2, WS_PRIV.getE1(), "ref1", WS_PRIV.getE1(), "html", 1);
	}

	private static void saveRef(
			final WorkspaceClient ws,
			final long wsid,
			final String wsname,
			final long refWsid,
			final String refWsname,
			final int refVersion) {
		// TODO Auto-generated method stub
		
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
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (final ZipOutputStream zos = new ZipOutputStream(
				baos, StandardCharsets.UTF_8);) {
		
			final ZipEntry ze = new ZipEntry(filename);
			zos.putNextEntry(ze);
			final byte[] b = contents.getBytes(StandardCharsets.UTF_8);
			zos.write(b, 0, b.length);
		}
		final String enc = Base64.getEncoder()
				.encodeToString(baos.toByteArray());
		saveEncodedZipFileToHTMLFileSet(ws, wsid, objname, enc);
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
		testSuccess(path, absref, TOKEN1.getToken(), "file2", false);
	}
	
	@Test
	public void testSuccessNamesFirstVerHeader() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/1/$/file.txt";
		final String absref = WS_READ.getE1() + "/1/1";
		testSuccess(path, absref, TOKEN1.getToken(), "file1", true);
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
		testSuccess(path, absref, TOKEN1.getToken(), "cachefile", true);
		//there's not really any way to easily ensure the code is reading
		//from the cache...
		testSuccess(path, absref, TOKEN1.getToken(), "cachefile", true);
	}
	
	@Test
	public void testSuccessIndexDotHtml() throws Exception {
		final String path = "/" + WS_READ.getE1() + "/index/-/$/";
		final String absref = WS_READ.getE1() + "/3/1";
		testSuccess(path, absref, TOKEN1.getToken(), "indexfile", "index.html",
				false);
	}
	
	@Test
	public void testFailNoRead() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 403, String.format(
				"Object html cannot be accessed: User %s may not " +
				"read workspace %s",
				TOKEN1.getUserName(), WS_PRIV.getE1()), false);
	}
	
	@Test
	public void testFailBadAuthCookie() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, "whee", 401, String.format(
				"Login failed! Invalid token",
				TOKEN1.getUserName(), WS_READ.getE1()), false);
	}
	
	@Test
	public void testFailBadAuthHeader() throws Exception {
		final String path = "/" + WS_PRIV.getE1() + "/html/-/$/file.txt";
		testFail(path, "whee", 401, String.format(
				"Login failed! Invalid token",
				TOKEN1.getUserName(), WS_READ.getE1()), true);
	}
	
	@Test
	public void testFailNoAuth() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		testFail(path, null, 403, String.format(
				"Object html cannot be accessed: Anonymous users may not " +
				"read workspace %s", WS_READ.getE2()), null);
	}
	
	@Test
	public void testFailNoSuchVersion() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/3/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404, String.format(
				"No object with id 1 (name html) and version 3 exists in " +
				"workspace %s", WS_READ.getE1()), false);
	}
	
	@Test
	public void testFailNoSuchObjectID() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/1000/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404, String.format(
				"No object with id 1000 exists in workspace %s",
				WS_READ.getE1()), false);
	}
	
	@Test
	public void testFailNoSuchObjectName() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/nope/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404, String.format(
				"No object with name nope exists in workspace %s",
				WS_READ.getE1()), false);
	}
	
	@Test
	public void testFailNoSuchWorkspaceID() throws Exception {
		final String path = "/100000000/html/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404,
				"Object html cannot be accessed: No workspace with id " +
				"100000000 exists", false);
	}
	
	@Test
	public void testFailNoSuchWorkspaceName() throws Exception {
		final String path = "/ireallyhopethiswsdoesntexist/html/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404,
				"Object html cannot be accessed: No workspace with name " +
				"ireallyhopethiswsdoesntexist exists", false);
	}
	
	@Test
	public void testFailDeletedObject() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/file.txt";
		final ObjectIdentity oi = new ObjectIdentity()
				.withWsid(WS_READ.getE1()).withName("html");
		WS1.deleteObjects(Arrays.asList(oi));
		try {
			testFail(path, TOKEN1.getToken(), 404, String.format(
					"Object 1 (name html) in workspace %s has been deleted",
					WS_READ.getE1()), false);
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
			testFail(path, TOKEN1.getToken(), 404, String.format(
					 "Object html cannot be accessed: Workspace %s is deleted",
					WS_READ.getE2()), false);
		} finally {
			WS1.undeleteWorkspace(wsi);
		}
	}
	
	@Test
	public void testFailNoPath() throws Exception {
		testFail("", TOKEN1.getToken(), 404, "Not Found", false);
	}
	
	@Test
	public void testFailNoVersion() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/$/file.txt";
		testFail(path, TOKEN1.getToken(), 404, "Not Found", false);
	}
	
	@Test
	public void testFailNoSeparator() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/file.txt";
		testFail(path, TOKEN1.getToken(), 404, "Not Found", false);
	}
	
	@Test
	public void testFailNoSlashPostSeparator() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/index/-/$";
		testFail(path, TOKEN1.getToken(), 404, "Not Found", false);
	}
	
	@Test
	public void testFailNoFile() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/html/-/$/bar.txt";
		testFail(path, TOKEN1.getToken(), 404, "Not Found", false);
	}
	
	@Test
	public void testFailNullEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/nullenc/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 500, "Unable to open the zip file",
				false);
	}
	
	@Test
	public void testFailNoEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/noenc/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 500, "Unable to open the zip file",
				false);
	}
	
	@Test
	public void testFailBadEncoding() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badenc/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 500, "Failed to decode the zip " +
				"file from the workspace object contents", false);
	}
	
	@Test
	public void testFailBadZip() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badzip/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 500, "Unable to open the zip file",
				false);
	}
	
	@Test
	public void testFailBadType() throws Exception {
		final String path = "/" + WS_READ.getE2() + "/badtype/-/$/file.txt";
		testFail(path, TOKEN1.getToken(), 400,
				"The type Empty.AType-1.0 cannot be processed by this service",
				false);
	}


	private void testFail(
			final String path,
			final String token,
			final int code,
			String error,
			final Boolean headerAuth)
			throws Exception {
		final URL u = new URL(HTTP_ENDPOINT.toString() + path);
		final HttpURLConnection hc = (HttpURLConnection) u.openConnection();
		if (headerAuth == null) {
			// do nothing
		} else if (headerAuth) {
			hc.setRequestProperty("Authorization", token);
		} else {
			hc.setRequestProperty("Cookie", "kbase_session=" + token);
		}
		hc.setDoInput(true);
		int gotcode = hc.getResponseCode();
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
			final Boolean headerAuth)
			throws Exception {
		testSuccess(path, absref, token, testcontents, "file.txt", headerAuth);
	}
	
	private void testSuccess(
			final String path,
			final String absref,
			final String token,
			final String testcontents,
			final String filename,
			final Boolean headerAuth)
			throws Exception {
		final URL u = new URL(HTTP_ENDPOINT.toString() + path);
		final HttpURLConnection hc = (HttpURLConnection) u.openConnection();
		if (headerAuth == null) {
			//to nothing
		} else if (headerAuth) {
			hc.setRequestProperty("Authorization", token);
		} else {
			hc.setRequestProperty("Cookie", "kbase_session=" + token);
		}
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

	private void assertNoTempFilesLeftOnDisk() throws IOException {
		final List<Path> tempfiles = new LinkedList<>();
		Files.newDirectoryStream(SCRATCH.resolve("temp"))
			.forEach(p -> tempfiles.add(p));
		for (final Path p: tempfiles) {
			Files.delete(p);
		}
		assertThat("Temp files left on disk", tempfiles,
				is(new LinkedList<>()));
	}
}
