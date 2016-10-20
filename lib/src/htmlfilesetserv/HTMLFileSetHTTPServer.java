package htmlfilesetserv;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.productivity.java.syslog4j.SyslogIF;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;

import us.kbase.auth.AuthConfig;
import us.kbase.auth.AuthException;
import us.kbase.auth.AuthToken;
import us.kbase.auth.ConfigurableAuthService;
import us.kbase.common.exceptions.UnimplementedException;
import us.kbase.common.service.JsonClientCaller;
import us.kbase.common.service.JsonClientException;
import us.kbase.common.service.JsonServerServlet;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.SyslogOutput;
import us.kbase.shock.client.BasicShockClient;
import us.kbase.shock.client.ShockNodeId;
import us.kbase.shock.client.exceptions.InvalidShockUrlException;
import us.kbase.shock.client.exceptions.ShockHttpException;
import us.kbase.shock.client.exceptions.ShockNoFileException;
import us.kbase.shock.client.exceptions.ShockNoNodeException;
import us.kbase.common.service.JsonTokenStream;
import us.kbase.common.service.ServerException;
import us.kbase.common.service.Tuple11;
import us.kbase.common.service.UObject;
import us.kbase.common.service.UnauthorizedException;
import us.kbase.typedobj.core.AbsoluteTypeDefId;
import us.kbase.typedobj.core.TypeDefName;
import us.kbase.workspace.GetObjectInfoNewParams;
import us.kbase.workspace.GetObjects2Params;
import us.kbase.workspace.ObjectData;
import us.kbase.workspace.ObjectSpecification;
import us.kbase.workspace.WorkspaceClient;

/** A server for the HTMLFileSet type.
 * 
 * Risks:
 * This service serves arbitrary files from the KBase stores, and any
 * user can save data to the KBase stores. This means that said user can
 * submit malicious code to KBase and have that code served up under the
 * KBase namespace.
 * It may be worthwhile to restrict creation privileges to specified users,
 * but based on the understanding of the use case this is not workable.
 * Caja (https://developers.google.com/caja/) might be useful for protecting
 * any front end widgets.
 * 
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class HTMLFileSetHTTPServer extends HttpServlet {
	
	//TODO TESTS
	//TODO ZZLATER cache reaper - need to keep date of last access & directory size (calculate during creation) in mem
	//TODO ZZLATER UI guys / thomason help with error page - defer indefinitely per Bill
	//TODO ZZEXTERNAL dynamic services should have data mounts
	//TODO ZZEXTERNAL BLOCKER kbase tokens are a garbled mess
	
	private final static String SERVICE_NAME = "HTMLFileSetServ";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String USER_AGENT = "User-Agent";
	private static final String CFG_SCRATCH = "scratch";
	private static final String CFG_WS_URL = "workspace-url";
	private static final String CFG_AUTH_URL = "auth-service-url";
	private static final String TEMP_DIR = "temp";
	private static final String CACHE_DIR = "cache";
	private static final String TOKEN_COOKIE_NAME = "kbase_session";
	private static final String ERROR_PAGE_PACKAGE = "htmlfilesetserv";
	private static final String ERROR_PAGE_NAME = "error.mustache";
	
	private static final Map<Integer, String> codeToLine = new HashMap<>();
	static {
		codeToLine.put(400, "Bad Request");
		codeToLine.put(401, "Unauthorized");
		codeToLine.put(403, "Forbidden");
		codeToLine.put(404, "Not Found");
		codeToLine.put(500, "Internal Server Error");
	}
		
	private final Map<TypeDefName, TypeHandler> handlers = new HashMap<>();
	private final Map<String, String> config;
	private final Path cachePath;
	private final Path temp;
	private final URL wsURL;
	private final ConfigurableAuthService auth;
	private final Mustache template;
	//TODO ZZLATER may need to make this a synchronized expiring cache
	private final Map<String, Object> locks = new HashMap<>();

	private static final String SERVER_CONTEXT_LOC = "/api/v1/*";
	private Integer jettyPort = null;
	private Server jettyServer = null;
	
	private interface TypeHandler {
	
		TypeDefName getHandledType();
		
		Path getZipFileIdentifier(Path zipFilePath)
				throws ZipIdentifierException;
		
		void getZipFile(
				AbsoluteTypeDefId type,
				Path zipFilePath,
				List<String> workspaceRefPath,
				Path zipfile,
				AuthToken token)
				throws IOException, ServerException, CorruptDataException,
					ZipIdentifierException, NotFoundException,
					DataRetrievalException;
	}
	
	private static class HTMLFileSetHandler implements TypeHandler {

		private final static TypeDefName TYPE = new TypeDefName(
				"HTMLFileSetUtils", "HTMLFileSet");
		
		private final URL wsURL;
		private final Path temp;
		
		public HTMLFileSetHandler(final URL workspaceURL, final Path tempdir) {
			wsURL = workspaceURL;
			temp = tempdir;
		}
		
		@Override
		public TypeDefName getHandledType() {
			return TYPE;
		}

		@Override
		public Path getZipFileIdentifier(final Path zipFilePath) {
			return Paths.get(".");
		}

		@Override
		public void getZipFile(
				final AbsoluteTypeDefId type,
				final Path zipFilePath,
				final List<String> workspaceRefPath,
				final Path zipfile,
				final AuthToken token) throws IOException, ServerException,
					CorruptDataException {
			final String absrefSafe = workspaceRefPath.get(
					workspaceRefPath.size() - 1).replace("/", "_");
			Path tf = null;
			Path enc = null;
			try {
			tf = Files.createTempFile(
					temp, "wsobj." + absrefSafe + ".", ".json.tmp");
			final UObject uo = saveObjectToFile(
					wsURL, workspaceRefPath, token, tf);
			enc = Files.createTempFile(
					temp, "encoded." + absrefSafe + ".", ".zip.b64.tmp");
			try (final JsonTokenStream jts = uo.getPlacedStream();) {
				jts.close();
				jts.setRoot(Arrays.asList(
						"result", "0", "data", "0", "data", "file"));
				jts.writeJson(enc.toFile());
			}
			base64DecodeJsonString(enc, zipfile);
			} finally {
				if (tf != null) {
					Files.delete(tf);
				}
				if (enc != null) {
					Files.delete(enc);
				}
			}
			
		}
		
	}

	private static class KBaseReportHandler implements TypeHandler {

		private final static TypeDefName TYPE = new TypeDefName(
				"KBaseReport", "Report");
		
		private final URL wsURL;
		
		public KBaseReportHandler(final URL workspaceURL) {
			wsURL = workspaceURL;
		}
		
		@Override
		public TypeDefName getHandledType() {
			return TYPE;
		}

		@Override
		public Path getZipFileIdentifier(final Path zipFilePath)
				throws ZipIdentifierException {
			getZipIndex(zipFilePath); //checks validity of zipfile id
			return zipFilePath.getName(0);
		}

		private int getZipIndex(final Path zipFilePath)
				throws ZipIdentifierException {
			final int index;
			try {
				index = Integer.parseInt(zipFilePath.getName(0).toString());
			} catch (NumberFormatException e) {
				throw new ZipIdentifierException("The zip identifier " +
						"section of the path must be a non-negative integer",
						e);
			}
			if (index < 0) {
				throw new ZipIdentifierException("The zip identifier " +
						"section of the path must be a non-negative integer");
			}
			return index;
		}

		@Override
		public void getZipFile(
				final AbsoluteTypeDefId type,
				final Path zipFilePath,
				final List<String> workspaceRefPath,
				final Path zipfile,
				final AuthToken token) throws IOException, ServerException,
					CorruptDataException, ZipIdentifierException,
					NotFoundException, DataRetrievalException {
			final String shockNodeURL = getShockNodeURL(
					type, zipFilePath, workspaceRefPath, token);
			final String[] shockURLAndNode = shockNodeURL.split("node/");
			if (shockURLAndNode.length != 2) {
				throw new CorruptDataException("Invalid shock node url: " +
						shockNodeURL);
			}
			downloadZipFileFromShock(shockURLAndNode[0], shockURLAndNode[1],
					zipfile, token);
		}

		private String getShockNodeURL(
				final AbsoluteTypeDefId type,
				final Path zipFilePath,
				final List<String> workspaceRefPath,
				final AuthToken token)
				throws ZipIdentifierException, IOException, ServerException,
					CorruptDataException, NotFoundException,
					DataRetrievalException {
			final int index = getZipIndex(zipFilePath);
			final Map<String, Object> rep = getObject(
					wsURL, workspaceRefPath, type, token);
			@SuppressWarnings("unchecked")
			final List<Map<String, String>> htmlLinks =
					(List<Map<String, String>>) rep.get("html_links");
			if (htmlLinks == null || htmlLinks.isEmpty()) {
				throw new NotFoundException(
						"This KBase report does not contain html links");
				
			}
			if (index >= htmlLinks.size()) {
				throw new NotFoundException(String.format(
						"Zip identifier %s exceeds number of zip files in " +
						"KBaseReport list", index));
			}
			return htmlLinks.get(index).get("URL");
		}
	}
	
	public static class ZipIdentifierException extends Exception {
		
		public ZipIdentifierException(final String message) {
			super(message);
		}

		public ZipIdentifierException(
				final String message,
				final Throwable cause) {
			super(message, cause);
		}
	}
	
	/**
	 * Creates a new HTMLFileSet server
	 * @throws ConfigurationException if the configuration is incorrect
	 * @throws JsonClientException  if the workspace couldn't be contacted.
	 * @throws IOException if the workspace couldn't be contacted.
	 */
	public HTMLFileSetHTTPServer() throws ConfigurationException,
			IOException, JsonClientException {
		super();
		stfuLoggers();
		config = getConfig();
		
		Path scratchPath = Paths.get(".");
		final String scratch = config.get(CFG_SCRATCH);
		if (scratch != null && !scratch.trim().isEmpty()) {
			scratchPath = Paths.get(config.get(CFG_SCRATCH));
		}
		scratchPath = scratchPath.normalize().toAbsolutePath();
		cachePath = scratchPath.resolve(CACHE_DIR);
		temp = scratchPath.resolve(TEMP_DIR);
		deleteDirectoryAndContents(cachePath);
		deleteDirectoryAndContents(temp);
		Files.createDirectories(temp);
		Files.createDirectories(cachePath);
		logString("Using cache directory " + cachePath);
		logString("Using temp directory " + temp);
		
		this.wsURL = getWorkspaceURL();
		
		final AuthConfig acf = new AuthConfig();
		final String authURL = config.get(CFG_AUTH_URL);
		if (authURL != null && !authURL.trim().isEmpty()) {
			try {
				acf.withKBaseAuthServerURL(new URL(authURL));
			} catch (MalformedURLException | URISyntaxException e) {
				throw new ConfigurationException(
						"Illegal auth url: " + authURL, e);
			}
		}
		auth = new ConfigurableAuthService(acf);
		
		final MustacheFactory mf = new DefaultMustacheFactory(
				ERROR_PAGE_PACKAGE);
		template = mf.compile(ERROR_PAGE_NAME);
		
		final HTMLFileSetHandler hfsh = new HTMLFileSetHandler(wsURL, temp);
		final KBaseReportHandler kbrh = new KBaseReportHandler(wsURL);
		
		handlers.put(hfsh.getHandledType(), hfsh);
		handlers.put(kbrh.getHandledType(), kbrh);
	}

	private void deleteDirectoryAndContents(final Path dir)
			throws IOException {
		if (!Files.isDirectory(dir)) {
			return;
		}
		Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(
					final Path file,
					final BasicFileAttributes attrs)
							throws IOException {
				Files.delete(file);
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(
					final Path dir,
					final IOException exc)
					throws IOException {
				Files.delete(dir);
				return FileVisitResult.CONTINUE;
			}

		});
	}
	
	private URL getWorkspaceURL()
			throws ConfigurationException, IOException,
			JsonClientException {
		final String wsURL = config.get(CFG_WS_URL);
		if (wsURL == null || wsURL.trim().isEmpty()) {
			throw new ConfigurationException(
					"Illegal workspace url: " + wsURL);
		}
		final URL url;
		try {
			url = new URL(wsURL);
		} catch (MalformedURLException e) {
			throw new ConfigurationException(
					"Illegal workspace url: " + wsURL, e);
		}
		final WorkspaceClient ws = new WorkspaceClient(url);
		logString(String.format("Contacted workspace version %s at %s",
				ws.ver(), url));
		return url;
	}
	
	private static void stfuLoggers() {
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME))
			.setLevel(ch.qos.logback.classic.Level.OFF);
	}

	private Map<String, String> getConfig() throws ConfigurationException {
		final JsonServerSyslog logger = new JsonServerSyslog(
				SERVICE_NAME, JsonServerServlet.KB_DEP,
				JsonServerSyslog.LOG_LEVEL_INFO, false);
		final List<String> configErr = new ArrayList<>();
		logger.changeOutput(new SyslogOutput() {
			@Override
			public void logToSystem(
					final SyslogIF log,
					final int level,
					final String message) {
				configErr.add(message);
			}
		});
		// getConfig() gets the service name from the env if it exists
		final Map<String, String> cfg = JsonServerServlet.getConfig(
				SERVICE_NAME, logger);
		if (!configErr.isEmpty()) {
			throw new ConfigurationException(configErr.get(0));
		}
		return cfg;
	}
	
	private void logErr(
			final int code,
			final Throwable error,
			final RequestInfo ri) {
		final String se;
		if (error instanceof ServerException) {
			final ServerException serv = (ServerException) error;
			if (serv.getData() != null && !serv.getData().trim().isEmpty()) {
				se = "\n" + ((ServerException) error).getData();
			} else {
				se = "";
			}
		} else {
			se = "";
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		error.printStackTrace(new PrintStream(baos));
		logMessage(String.format("%s %s %s %s %s %s%s%s", ri.path, code,
				ri.userName, ri.ipAddress, ri.requestID, ri.userAgent, se,
				"\n" + new String(baos.toByteArray(),
						StandardCharsets.UTF_8)));
	}
	
	private void logMessage(final String message, final RequestInfo ri) {
		logMessage(String.format("%s %s %s", message, ri.userName,
				ri.requestID));
	}
	
	private void logMessage(final int code, final RequestInfo ri) {
		logMessage(String.format("%s %s %s %s %s %s", ri.path, code,
				ri.userName, ri.ipAddress, ri.requestID, ri.userAgent));
	}
	
	private void logMessage(final String message) {
		logString("GET " + message);
	}
	
	private void logString(final String message) {
		final double time = System.currentTimeMillis() / 1000.0;
		System.out.println(String.format("%.3f: %s", time, message));
	}
	
	private static class ConfigurationException extends Exception {
		
		public ConfigurationException(final String message) {
			super(message);
		}

		public ConfigurationException(
				final String message,
				final Throwable cause) {
			super(message, cause);
		}
	}
	
	@Override
	protected void doOptions(
			final HttpServletRequest request,
			final HttpServletResponse response)
			throws ServletException, IOException {
		JsonServerServlet.setupResponseHeaders(request, response);
		response.setContentLength(0);
		response.getOutputStream().print("");
		response.getOutputStream().flush();
	}
	
	private class RequestInfo {
		
		public final String userName;
		public final String ipAddress;
		public final String path;
		public final String userAgent;
		public final String requestID;
		
		public RequestInfo(
				final String userName,
				final String ipAddress,
				final String userAgent,
				final String path) {
			super();
			this.userName = userName;
			this.ipAddress = ipAddress;
			this.userAgent = userAgent;
			this.path = path;
			this.requestID = ("" + Math.random()).substring(2);
		}
	}
	
	@Override
	protected void doGet(
			final HttpServletRequest request,
			final HttpServletResponse response)
			throws ServletException, IOException {
		
		final RequestInfo ri;
	
		final AuthToken token;
		try {
			token = getToken(request);
			final String user = token == null ? "-" : token.getUserName();
			ri = buildRequestInfo(request, user);
		} catch (AuthException e) {
			final RequestInfo ri2 = buildRequestInfo(request, "-");
			logHeaders(request, ri2);
			handleErr(401, e, ri2, response);
			return;
		} catch (IOException e) {
			final RequestInfo ri2 = buildRequestInfo(request, "-");
			logHeaders(request, ri2);
			handleErr(500, e, ri2, response);
			return;
		}
		logHeaders(request, ri);
		
		String path = request.getPathInfo();
		
		if (path == null || path.trim().isEmpty()) { // e.g. /api/v1
			handleErr(404, "Empty path", ri, response);
			return;
		}
		if (path.endsWith("/")) { // e.g. /docs/
			path = path + "index.html";
		}

		// the path is already normalized by the framework, so no need to
		// normalize here
		final Path local;
		try {
			local = setUpCache(path, token, ri);
		} catch (NotFoundException e) {
			handleErr(404, e, ri, response);
			return;
		} catch (IOException | CorruptDataException |
				DataRetrievalException e) {
			handleErr(500, e, ri, response);
			return;
		} catch (ServerException e) {
			handleWSServerError(ri, e, response);
			return;
		} catch (ZipIdentifierException e) {
			handleErr(400, e, ri, response);
			return;
		}
		
		if (!Files.isRegularFile(local)) {
			handleErr(404, "Not Found", ri, response);
			return;
		}
		try {
			try (final InputStream is = Files.newInputStream(local)) {
				IOUtils.copy(is, response.getOutputStream());
			}
		} catch (IOException ioe) {
			handleErr(500, ioe, ri, response);
			return;
		}
		logMessage(200, ri);
	}

	private void handleErr(
			final int code,
			// might want to have a string to override the throwable error
			// message?
			final Throwable error,
			final RequestInfo ri,
			final HttpServletResponse response) throws IOException {
		logErr(code, error, ri);
		response.setStatus(code);
		writeErrorPage(code, error.getMessage(), ri, response);
	}
	
	private void handleErr(
			final int code,
			// might want to have a string to override the throwable error
			// message?
			final String error,
			final RequestInfo ri,
			final HttpServletResponse response) throws IOException {
		logMessage(code, ri);
		response.setStatus(code);
		writeErrorPage(code, error, ri, response);
	}

	private void writeErrorPage(
			final int code,
			final String error,
			final RequestInfo ri,
			final HttpServletResponse response)
			throws IOException {
		final Map<String, Object> model = new HashMap<>();
		model.put("callID", ri.requestID);
		model.put("time", new Date().getTime());
		model.put("httpCode", code);
		model.put("httpStatus", codeToLine.get(code));
		model.put("message", error);
		template.execute(response.getWriter(), model);
	}

	private RequestInfo buildRequestInfo(
			final HttpServletRequest request,
			final String userName) {
		return new RequestInfo(
				userName,
				JsonServerServlet.getIpAddress(request, config),
				request.getHeader(USER_AGENT),
				request.getRequestURI());
	}

	private void handleWSServerError(
			final RequestInfo ri,
			final ServerException e,
			final HttpServletResponse response) throws IOException {
		int code = 400;
		String m = e.getMessage();
		if (m.contains("may not read")) {
			code = 403;
		} else if (m.contains("No object with") ||
				m.contains("has been deleted") ||
				m.contains("is deleted") ||
				m.contains("No workspace with")) {
			code = 404;
		}
		if (m.contains("ObjectSpecification")) {
			m = m.split(":")[1];
		}
		if (m.contains("Reference chain #1, position")) {
			m = m.replaceFirst(" #1,", "");
		}
		logErr(code, e, ri);
		response.setStatus(code);
		writeErrorPage(code, m, ri, response);
	}

	private AuthToken getToken(final HttpServletRequest request)
			throws IOException, AuthException {
		final String at = request.getHeader("Authorization");
		if (at != null && !at.trim().isEmpty()) {
			return auth.validateToken(at);
		}
		if (request.getCookies() != null) {
			for (final Cookie c: request.getCookies()) {
				if (c.getName().equals(TOKEN_COOKIE_NAME)) {
					return auth.validateToken(c.getValue());
				}
			}
		}
		return null;
	}

	private static class NotFoundException extends Exception {
		
		public NotFoundException() {
			super("Not Found");
		}
		
		public NotFoundException(final String message) {
			super(message);
		}
		
	}
	
	private Path setUpCache(
			final String path,
			final AuthToken token,
			final RequestInfo ri)
			throws NotFoundException, IOException, ServerException,
			CorruptDataException, ZipIdentifierException,
			DataRetrievalException {
		final ResolvedPaths refsAndPath = splitRefsAndPath(path);
		final List<String> refpath = refsAndPath.refpath;

		final AbsRefAndType absrefAndType =
				getAbsoluteRef(refpath, token);
		final String absref = absrefAndType.absref;
		refpath.set(refpath.size() - 1, absref);
		final TypeHandler handler = handlers.get(absrefAndType.type.getType());
		if (handler == null) {
			throw new ServerException(String.format(
					"The type %s cannot be processed by this service",
					absrefAndType.type.getTypePrefix()), -1, "TypeError");
		}
		final Path zipID = handler.getZipFileIdentifier(refsAndPath.path);
		
		final Path cacheLoc = cachePath.resolve(absref).resolve(zipID);
		final Path filepath = cachePath.resolve(absref)
				.resolve(refsAndPath.path);
		synchronized (this) {
			if (!locks.containsKey(absref)) {
				locks.put(absref, new Object());
			}
		}
		synchronized (locks.get(absref)) {
			if (Files.isDirectory(cacheLoc)) {
				logMessage("Using cache for object " + absref, ri);
				return filepath;
			}
			
			final String absrefSafe = absref.replace("/", "_");
			Path zip = null;
			try {
				zip = Files.createTempFile(temp, absrefSafe + ".", ".zip.tmp");
				handler.getZipFile(absrefAndType.type, refsAndPath.path,
						refpath, zip, token);
				unzip(cacheLoc, zip);
			} finally {
				if (zip != null) {
					Files.delete(zip);
				}
			}
		}
		return filepath;
	}

	private static void base64DecodeJsonString(
			final Path encoded,
			final Path unencoded) throws CorruptDataException {
		try (final OutputStream os = new BufferedOutputStream(
					Files.newOutputStream(unencoded));
				final InputStream is = Files.newInputStream(encoded)) {
			final InputStream iswrap = new RemoveFirstAndLast(
					new BufferedInputStream(is), Files.size(encoded));
			IOUtils.copy(Base64.getDecoder().wrap(iswrap), os);
		} catch (IOException e) {
			throw new CorruptDataException("Failed to decode the zip file " +
					"from the workspace object contents", e);
		}
	}
	
	public static class CorruptDataException extends Exception {
		
		public CorruptDataException(final String message) {
			super(message);
		}
		
		public CorruptDataException(
				final String message,
				final Throwable cause) {
			super(message, cause);
		}
	}
	
	public static class DataRetrievalException extends Exception {
		
		public DataRetrievalException(final String message) {
			super(message);
		}
		
		public DataRetrievalException(
				final String message,
				final Throwable cause) {
			super(message, cause);
		}
	}
	
	private AbsRefAndType getAbsoluteRef(
			final List<String> refpath,
			final AuthToken token)
			throws IOException, ServerException {
		
		final WorkspaceClient ws = getWorkspaceClient(wsURL, token);
		
		try {
			final ObjectSpecification os = buildObjectSpecification(refpath);
			final Tuple11<Long, String, String, String, Long, String, Long,
				String, String, Long, Map<String, String>> info =
					ws.getObjectInfoNew(new GetObjectInfoNewParams()
							.withIncludeMetadata(0L)
							.withObjects(Arrays.asList(os)))
					.get(0);
			final AbsoluteTypeDefId type = AbsoluteTypeDefId
					.fromAbsoluteTypeString(info.getE3());
			final String absref =  info.getE7() + "/" + info.getE1() + "/" +
					info.getE5();
			return new AbsRefAndType(absref, type);
		} catch (JsonClientException e) {
			if (e instanceof ServerException) {
				throw (ServerException) e;
			}
			// should never happen - indicates result couldn't be parsed
			throw new RuntimeException("Something is very badly wrong with " +
					"the workspace server", e);
		}
	}

	private static WorkspaceClient getWorkspaceClient(
			final URL wsURL,
			final AuthToken token)
			throws IOException {
		final WorkspaceClient ws;
		if (token == null) {
			ws = new WorkspaceClient(wsURL);
		} else {
			try {
				ws = new WorkspaceClient(wsURL, token);
			} catch (UnauthorizedException e) {
				throw new RuntimeException("This is impossible, neat", e);
			}
		}
		return ws;
	}

	private static ObjectSpecification buildObjectSpecification(
			final List<String> refpath) {
		final ObjectSpecification os = new ObjectSpecification();
		if (refpath.size() > 1) {
			os.withRef(refpath.get(0));
			os.withObjRefPath(refpath.subList(1, refpath.size()));
		} else {
			os.withRef(refpath.get(0));
		}
		return os;
	}

	private static class RemoveFirstAndLast extends InputStream {
		
		final InputStream wrapped;
		final long size;
		long read;
		
		public RemoveFirstAndLast(
				final InputStream wrapped,
				final long size) throws IOException {
			this.wrapped = wrapped;
			this.size = size;
			wrapped.read(); // discard first byte
			this.read = 1;
		}

		// base64 decoder only uses this method.
		@Override
		public int read() throws IOException {
			if (read >= size - 1) {
				return -1;
			}
			read++;
			return wrapped.read();
		}
		
		@Override
		public int read(final byte[] b) {
			throw new UnimplementedException();
		}
		
		@Override
		public int read(final byte[] b, final int off, final int len) {
			throw new UnimplementedException();
		}
		
	}

	private void unzip(
			final Path targetDir,
			final Path zipfile)
			throws IOException, CorruptDataException {
		try (final ZipFile zf = new ZipFile(zipfile.toFile())) {
			for (Enumeration<? extends ZipEntry> e = zf.entries();
					e.hasMoreElements();) {
				final ZipEntry ze = e.nextElement();
				final Path file = targetDir.resolve(ze.getName());
				Files.createDirectories(file.getParent());
				Files.createFile(file);
				try (final OutputStream os = Files.newOutputStream(file);
						final InputStream is = zf.getInputStream(ze)) {
					IOUtils.copy(is, os);
				}
			}
		} catch (ZipException e) {
			throw new CorruptDataException("Unable to open the zip file", e);
		}
	}

	private static Map<String, Object> getObject(
			final URL wsURL,
			final List<String> refPath,
			final AbsoluteTypeDefId type,
			final AuthToken token)
			throws IOException, ServerException, CorruptDataException,
				DataRetrievalException {
		final WorkspaceClient ws = getWorkspaceClient(wsURL, token);

		try {
			final ObjectData obj = ws.getObjects2(
					new GetObjects2Params().withObjects(Arrays.asList(
							buildObjectSpecification(refPath))))
					.getData().get(0);

			// not really any way to test the next two if statements without
			// setting up an insane test rig
			if (!obj.getInfo().getE3().equals(type.getTypePrefix())) {
				throw new CorruptDataException("Workspace type changed " +
						"between calls, something is very wrong");
			}
			if (obj.getHandleError() != null ||
					obj.getHandleStacktrace() != null) {
				throw new DataRetrievalException(String.format(
						"Workspace reported a handle error: %s\n%s",
						obj.getHandleError(), obj.getHandleStacktrace()));
			}
			@SuppressWarnings("unchecked")
			final Map<String, Object> o = obj.getData()
					.asClassInstance(Map.class);
			return o;
		} catch (JsonClientException e) {
			if (e instanceof ServerException) {
				throw (ServerException) e;
			}
			// should never happen - indicates result couldn't be parsed
			throw new RuntimeException("Something is very badly wrong with " +
					"the workspace server", e);
		}
	}
	
	private static UObject saveObjectToFile(
			final URL wsURL,
			final List<String> refpath,
			final AuthToken token,
			final Path tempfile)
			throws IOException, ServerException {
		final JsonClientCaller ws;
		if (token == null) {
			ws = new JsonClientCaller(wsURL);
		} else {
			try {
				ws = new JsonClientCaller(wsURL, token);
			} catch (UnauthorizedException e) {
				throw new RuntimeException("This is impossible, neat", e);
			}
		}
		ws.setFileForNextRpcResponse(tempfile.toFile());
		final Map<String, List<ObjectSpecification>> arg = new HashMap<>();
		arg.put("objects", Arrays.asList(buildObjectSpecification(refpath)));
		try {
			return ws.jsonrpcCall("Workspace.get_objects2", Arrays.asList(arg),
					new TypeReference<UObject>() {}, true, false);
		} catch (JsonClientException e) {
			if (e instanceof ServerException) {
				throw (ServerException) e;
			}
			// should never happen - indicates result couldn't be parsed
			throw new RuntimeException("Something is very badly wrong with " +
					"the workspace server", e);
		}
	}
	

	private static void downloadZipFileFromShock(
			final String shockURLString,
			final String shockNode,
			final Path zipfile,
			final AuthToken token)
			throws CorruptDataException, IOException, DataRetrievalException {
		final URL shockURL;
		try {
			shockURL = new URL(shockURLString);
		} catch (MalformedURLException e) {
			throw new CorruptDataException("Invalid shock URL: " +
					shockURLString, e);
		}
		final BasicShockClient bsc;
		try {
			bsc = new BasicShockClient(shockURL);
		} catch (InvalidShockUrlException e) {
			throw new CorruptDataException("Invalid shock URL: " +
					shockURL, e);
		}
		// adding the token later prevents the client from creating and
		// deleting a shock node on startup
		bsc.updateToken(token);
		try (final OutputStream out = new BufferedOutputStream(
				Files.newOutputStream(zipfile))) {
			bsc.getFile(new ShockNodeId(shockNode), out);
		} catch (ShockNoNodeException e) {
			throw new CorruptDataException("No such shock node: " +
					shockNode, e);
		} catch (ShockNoFileException e) {
			throw new CorruptDataException(String.format(
					"The shock node %s has no file", shockNode, e));
		} catch (ShockHttpException e) {
			// no reasonable way to test this, something's seriously screwed up
			throw new DataRetrievalException(
					"Unable to download zip file from shock", e);
		} catch (IllegalArgumentException e) {
			throw new CorruptDataException("Invalid shock node ID: " +
					shockNode, e);
		}
	}
	
	private static class ResolvedPaths {
		
		public final List<String> refpath;
		public final Path path;
		
		public ResolvedPaths(final List<String> refpath, final Path path) {
			super();
			this.refpath = refpath;
			this.path = path;
		}
	}
	
	private static class AbsRefAndType {
		
		public final String absref;
		public final AbsoluteTypeDefId type;
		
		public AbsRefAndType(
				final String absref,
				final AbsoluteTypeDefId type) {
			super();
			this.absref = absref;
			this.type = type;
		}
	}

	private ResolvedPaths splitRefsAndPath(String path)
			throws NotFoundException {
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		final String[] wsAndPath  = path.split("\\$", 2);
		if (wsAndPath.length != 2) {
			throw new NotFoundException();
		}
		String localPath = wsAndPath[1];
		if (!localPath.startsWith("/")) {
			throw new NotFoundException();
		}
		localPath = localPath.substring(1, localPath.length());
		final String[] s = wsAndPath[0].split("/");
		if (s.length % 3 != 0) {
			throw new NotFoundException();
		}
		final List<String> refpath = new LinkedList<>();
		for (int i = 0; i < s.length; i ++) {
			String ref = s[i] + "/" + s[i + 1];
			if (!"-".equals(s[i + 2])) {
				ref += "/" + s[i + 2];
			}
			i += 2;
			refpath.add(ref);
		}
		return new ResolvedPaths(refpath, Paths.get(localPath));
	}

	private void logHeaders(
			final HttpServletRequest req,
			final RequestInfo ri) {
		final String xFF = req.getHeader(X_FORWARDED_FOR);
		if (xFF != null && !xFF.isEmpty()) {
			logMessage(X_FORWARDED_FOR + ": " + xFF, ri);
		}
	}
	
	/**
	 * Starts a test jetty doc server on an OS-determined port at /docs. Blocks
	 * until the server is terminated.
	 * @throws Exception if the server couldn't be started.
	 */
	public void startupServer() throws Exception {
		startupServer(0);
	}
	
	/**
	 * Starts a test jetty doc server at /docs. Blocks until the
	 * server is terminated.
	 * @param port the port to which the server will connect.
	 * @throws Exception if the server couldn't be started.
	 */
	public void startupServer(int port) throws Exception {
		jettyServer = new Server(port);
		ServletContextHandler context =
				new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		jettyServer.setHandler(context);
		context.addServlet(new ServletHolder(this), SERVER_CONTEXT_LOC);
		jettyServer.start();
		jettyPort = jettyServer.getConnectors()[0].getLocalPort();
		jettyServer.join();
	}
	
	/**
	 * Get the jetty test server port. Returns null if the server is not
	 * running or starting up.
	 * @return the port
	 */
	public Integer getServerPort() {
		return jettyPort;
	}
	
	/**
	 * Stops the test jetty server.
	 * @throws Exception if there was an error stopping the server.
	 */
	public void stopServer() throws Exception {
		jettyServer.stop();
		jettyServer = null;
		jettyPort = null;
		
	}
	
	public static void main(String[] args) throws Exception {
		new HTMLFileSetHTTPServer().startupServer(10000);
	}
}
