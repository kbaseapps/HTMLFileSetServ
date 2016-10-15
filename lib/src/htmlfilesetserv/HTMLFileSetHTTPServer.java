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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import us.kbase.common.service.JsonTokenStream;
import us.kbase.common.service.ServerException;
import us.kbase.common.service.Tuple11;
import us.kbase.common.service.UObject;
import us.kbase.common.service.UnauthorizedException;
import us.kbase.workspace.GetObjectInfoNewParams;
import us.kbase.workspace.ObjectSpecification;
import us.kbase.workspace.WorkspaceClient;

/** A server for the HTMLFileSet type.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class HTMLFileSetHTTPServer extends HttpServlet {
	
	//TODO TESTS
	//TODO JAVADOC
	//TODO ZZLATER cache reaper - need to keep date of last access in mem
	//TODO EXTERNAL dynamic service logs should be restricted to admins
	//TODO EXTERNAL dyanmic services should have data mounts
	
	private final static String SERVICE_NAME = "HTMLFileSetServ";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String USER_AGENT = "User-Agent";
	private static final String CFG_SCRATCH = "scratch";
	private static final String CFG_WS_URL = "workspace-url";
	private static final String CFG_AUTH_URL = "auth-service-url";
	private static final String TEMP_DIR = "temp";
	private static final String ERROR_PAGE_PACKAGE = "htmlfilesetserv";
	private static final String ERROR_PAGE_NAME = "error.mustache";
	
	private static final String TYPE_HTMLFILSET =
			"HTMLFileSetUtils.HTMLFileSet";
	
	
	private static final Map<Integer, String> codeToLine = new HashMap<>();
	static {
		codeToLine.put(400, "Bad Request");
		codeToLine.put(401, "Unauthorized");
		codeToLine.put(403, "Forbidden");
		codeToLine.put(404, "Not Found");
		codeToLine.put(500, "Internal Server Error");
	}
		
	private final Map<String, String> config;
	private final Path scratch;
	private final Path temp;
	private final URL wsURL;
	private final ConfigurableAuthService auth;
	private final Mustache template;
	//TODO ZZLATER may need to make this a synchronized expiring cache
	private final Map<String, Object> locks = new HashMap<>();

	private static final String SERVER_CONTEXT_LOC = "/api/v1/*";
	private Integer jettyPort = null;
	private Server jettyServer = null;
	

	// could make custom 404 page at some point
	// http://www.eclipse.org/jetty/documentation/current/custom-error-pages.html
	
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
		
		final String scratch = config.get(CFG_SCRATCH);
		if (scratch == null || scratch.trim().isEmpty()) {
			this.scratch = Paths.get(".").normalize().toAbsolutePath();
		} else {
			this.scratch = Paths.get(config.get("scratch"))
					.normalize().toAbsolutePath();
		}
		this.temp = this.scratch.resolve(TEMP_DIR);
		Files.createDirectories(this.temp);
		logString("Using directory " + this.scratch + " for cache");
		
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
	
	public static void stfuLoggers() {
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
			handleErr(404, "Not Found", ri, response);
			return;
		}
		if (path.endsWith("/")) { // e.g. /docs/
			path = path + "index.html";
		}

		final String[] refpaths = request.getParameterValues("refpath");
		final String refpath = refpaths == null || refpaths.length == 0 ?
				null : refpaths[0];
		// the path is already normalized by the framework, so no need to
		// normalize here
		final Path full;
		try {
			full = setUpCache(path, token, ri, refpath);
		} catch (NotFoundException e) {
			handleErr(404, "Not Found", ri, response);
			return;
		} catch (IOException e) {
			handleErr(500, e, ri, response);
			return;
		} catch (ServerException e) {
			handleWSServerError(ri, e, response);
			return;
		}
		
		if (!Files.isRegularFile(full)) {
			handleErr(404, "Not Found", ri, response);
			return;
		}
		try {
			try (final InputStream is = Files.newInputStream(full)) {
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
		//TODO NOW check various exceptions - no such ws, obj, not authorized to ws, bad input, and handle errors better
		handleErr(400, e, ri, response);
	}

	private AuthToken getToken(final HttpServletRequest request)
			throws IOException, AuthException {
		final String at = request.getHeader("Authorization");
		if (at != null && !at.trim().isEmpty()) {
			return auth.validateToken(at);
		}
		if (request.getCookies() != null) {
			for (final Cookie c: request.getCookies()) {
				if (c.getName().equals("token")) {
					return auth.validateToken(c.getValue());
				}
			}
		}
		return null;
	}

	private static class NotFoundException extends Exception {}
	
	private Path setUpCache(
			final String path,
			final AuthToken token,
			final RequestInfo ri,
			final String refpath)
			throws NotFoundException, IOException, ServerException {
		final RefAndPath refAndPath = splitRefAndPath(path);
		final List<String> refpathlist;
		if (refpath == null) {
			refpathlist = null;
		} else {
			refpathlist = Arrays.asList(refpath.split(","));
			for (int i = 0; i < refpathlist.size(); i++) {
				refpathlist.set(i, refpathlist.get(i).trim());
			}
		}
		final String absref = getAbsoluteRef(refAndPath.ref, token,
				refpathlist);
		
		final Path rootpath = scratch.resolve(absref);
		final Path filepath = rootpath.resolve(refAndPath.path);
		synchronized (this) {
			if (!locks.containsKey(absref)) {
				locks.put(absref, new Object());
			}
		}
		synchronized (locks.get(absref)) {
			if (Files.isDirectory(rootpath)) {
				logMessage("Using cache for object " + absref, ri);
				return filepath;
			}
			final String absrefSafe = absref.replace("/", "_");
			final Path tf = Files.createTempFile(
					temp, "wsobj." + absrefSafe + ".", ".json.tmp");
			final UObject uo = saveObjectToFile(token, absref, tf, refpathlist);
			final Path enc = Files.createTempFile(
					temp, "encoded." + absrefSafe + ".", ".zip.b64.tmp");
			try (final JsonTokenStream jts = uo.getPlacedStream();) {
				jts.close();
				jts.setRoot(Arrays.asList(
						"result", "0", "data", "0", "data", "file"));
				jts.writeJson(enc.toFile());
			}
			Files.delete(tf);
			final Path zip = Files.createTempFile(
					temp, absrefSafe + ".", ".zip.tmp");
			try (final OutputStream os = new BufferedOutputStream(
						Files.newOutputStream(zip));
					final InputStream is = Files.newInputStream(enc)) {
				final InputStream iswrap = new RemoveFirstAndLast(
						new BufferedInputStream(is), Files.size(enc));
				IOUtils.copy(Base64.getDecoder().wrap(iswrap), os);
			}
			Files.delete(enc);
			unzip(rootpath, zip);
			Files.delete(zip);
		}
		return filepath;
	}
	
	private String getAbsoluteRef(
			final String ref,
			final AuthToken token,
			final List<String> refpathlist)
			throws IOException, ServerException {
		
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
		
		try {
			final ObjectSpecification os = buildObjectSpecification(
					ref, refpathlist);
			final Tuple11<Long, String, String, String, Long, String, Long,
				String, String, Long, Map<String, String>> info =
					ws.getObjectInfoNew(new GetObjectInfoNewParams()
							.withIncludeMetadata(0L)
							.withObjects(Arrays.asList(os)))
					.get(0);
			if (!info.getE3().startsWith(TYPE_HTMLFILSET)) {
				throw new ServerException(String.format(
						"The type %s cannot be processed by this service",
						info.getE3()), -1, "TypeError");
			}
			return info.getE7() + "/" + info.getE1() + "/" + info.getE5();
		} catch (JsonClientException e) {
			if (e instanceof ServerException) {
				throw (ServerException) e;
			}
			// should never happen - indicates result couldn't be parsed
			throw new RuntimeException("Something is very badly wrong with " +
					"the workspace server", e);
		}
	}

	private ObjectSpecification buildObjectSpecification(
			final String ref,
			final List<String> refpathlist) {
		final ObjectSpecification os = new ObjectSpecification();
		if (refpathlist != null) {
			os.withRef(refpathlist.get(0));
			final List<String> newpath = new LinkedList<>();
			newpath.addAll(refpathlist.subList(1, refpathlist.size()));
			newpath.add(ref);
			os.withObjRefPath(newpath);
		} else {
			os.withRef(ref);
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
			throws IOException {
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
		}
	}

	private UObject saveObjectToFile(
			final AuthToken token,
			final String absref,
			final Path tempfile,
			final List<String> refpathlist)
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
		arg.put("objects", Arrays.asList(buildObjectSpecification(
				absref, refpathlist)));
		final UObject uo;
		try {
			uo = ws.jsonrpcCall("Workspace.get_objects2", Arrays.asList(arg),
					new TypeReference<UObject>() {}, true, true);
		} catch (JsonClientException e) {
			if (e instanceof ServerException) {
				throw (ServerException) e;
			}
			// should never happen - indicates result couldn't be parsed
			throw new RuntimeException("Something is very badly wrong with " +
					"the workspace server", e);
		}
		return uo;
	}
	
	private static class RefAndPath {
		
		public final String ref;
		public final Path path;
		
		public RefAndPath(final String ref, final Path path) {
			super();
			this.ref = ref;
			this.path = path;
		}
	}

	private RefAndPath splitRefAndPath(String path) throws NotFoundException {
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		final String[] s = path.split("/", 4);
		if (s.length != 4) {
			throw new NotFoundException();
		}
		String ref = s[0] + "/" + s[1];
		if (!"-".equals(s[2])) {
			ref += "/" + s[2];
		}
		return new RefAndPath(ref, Paths.get(s[3]));
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
