package htmlfilesetserv;

import java.io.BufferedInputStream;
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
import java.util.Enumeration;
import java.util.HashMap;
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

import us.kbase.auth.AuthConfig;
import us.kbase.auth.AuthException;
import us.kbase.auth.AuthToken;
import us.kbase.auth.ConfigurableAuthService;
import us.kbase.common.exceptions.UnimplementedException;
import us.kbase.common.service.JsonClientCaller;
import us.kbase.common.service.JsonClientException;
import us.kbase.common.service.JsonServerServlet;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.RpcInfo;
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
	
	//TODO NOW TESTS
	//TODO NOW JAVADOC
	//TODO NOW pass workspace ref path as parameter
	//TODO NOW better error html page
	
	private final static String SERVICE_NAME = "HTMLFileSetServ";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String USER_AGENT = "User-Agent";
	private static final String CFG_SCRATCH = "scratch";
	private static final String CFG_WS_URL = "workspace-url";
	private static final String CFG_AUTH_URL = "auth-service-url";
	private static final String TEMP_DIR = "temp";
	
	private final Map<String, String> config;
	private final Path scratch;
	private final Path temp;
	private final URL wsURL;
	private final ConfigurableAuthService auth;
	
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
		logthis("Using directory " + this.scratch + " for cache", true);
		
		final String wsURL = config.get(CFG_WS_URL);
		if (wsURL == null || wsURL.trim().isEmpty()) {
			throw new ConfigurationException(
					"Illegal workspace url: " + wsURL);
		}
		try {
			this.wsURL = new URL(wsURL);
		} catch (MalformedURLException e) {
			throw new ConfigurationException(
					"Illegal workspace url: " + wsURL, e);
		}
		final WorkspaceClient ws = new WorkspaceClient(this.wsURL);
		logthis(String.format("Contacted workspace version %s at %s",
				ws.ver(), this.wsURL), true);
		
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
	
	private void logerr(
			final HttpServletRequest request,
			final HttpServletResponse response,
			final int code,
			final Throwable error)
			throws IOException {
		final String se;
		if (error instanceof ServerException) {
			se = "\n" + ((ServerException) error).getData();
		} else {
			se = "";
		}
		logthis(request.getRequestURI() + " " + code + " " +
				request.getHeader(USER_AGENT) + se, error);
		response.sendError(code);
	}
	
	private void logthis(final String message) {
		logthis(message, false);
	}
	
	private void logthis(final String message, boolean noGet) {
		final double time = System.currentTimeMillis() / 1000.0;
		final String get = noGet ? ": " : ": GET ";
		System.out.println(time + get + message);
	}
	
	private void logthis(final String message, final Throwable t) {
		final double time = System.currentTimeMillis() / 1000.0;
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		t.printStackTrace(new PrintStream(baos));
		System.out.print(time + ": GET " + message + "\n" +
				new String(baos.toByteArray(), StandardCharsets.UTF_8));
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
	
	@Override
	protected void doGet(
			final HttpServletRequest request,
			final HttpServletResponse response)
			throws ServletException, IOException {
		
		//TODO NOW log IP address everywhere
		final RpcInfo rpc = JsonServerSyslog.getCurrentRpcInfo();
		rpc.setId(("" + Math.random()).substring(2));
		rpc.setIp(JsonServerServlet.getIpAddress(request, config));
		rpc.setMethod("GET");
		logHeaders(request);
	
		final AuthToken token;
		try {
			token = getToken(request);
		} catch (AuthException e) {
			logerr(request, response, 401, e);
			return;
		} catch (IOException e) {
			logerr(request, response, 500, e);
			return;
		}
		
		String path = request.getPathInfo();
		
		if (path == null || path.trim().isEmpty()) { // e.g. /api/v1
			handle404(request, response);
			return;
		}
		if (path.endsWith("/")) { // e.g. /docs/
			path = path + "index.html";
		}
		// the path is already normalized by the framework, so no need to
		// normalize here
		final Path full;
		try {
			full = setUpCache(path, token);
		} catch (NotFoundException e) {
			handle404(request, response);
			return;
		} catch (IOException e) {
			logerr(request, response, 500, e);
			return;
		} catch (ServerException e) {
			handleWSServerError(request, response, e);
			return;
		}
		
		if (!Files.isRegularFile(full)) {
			handle404(request, response);
			return;
		}
		try {
			try (final InputStream is = Files.newInputStream(full)) {
				IOUtils.copy(is, response.getOutputStream());
			}
		} catch (IOException ioe) {
			logthis(request.getRequestURI() + " 500 " +
					request.getHeader(USER_AGENT), ioe);
			response.sendError(500);
			return;
		}
		logthis(request.getRequestURI() + " 200 " +
				request.getHeader(USER_AGENT));
	}

	private void handleWSServerError(
			final HttpServletRequest request,
			final HttpServletResponse response,
			final ServerException e)
			throws IOException {
		//TODO NOW test various exceptions - no such ws, obj, not authorized to ws, bad input, and handle errors better
		logerr(request, response, 400, e);
	}

	private AuthToken getToken(final HttpServletRequest request)
			throws IOException, AuthException {
		final String at = request.getHeader("Authorization");
		if (at != null && !at.trim().isEmpty()) {
			return auth.validateToken(at);
		}
		for (final Cookie c: request.getCookies()) {
			if (c.getName().equals("token")) {
				return auth.validateToken(c.getValue());
			}
		}
		return null;
	}

	private static class NotFoundException extends Exception {}
	
	private Path setUpCache(
			final String path,
			final AuthToken token)
			throws NotFoundException, IOException, ServerException {
		final RefAndPath refAndPath = splitRefAndPath(path);
		final String absref = getAbsoluteRef(refAndPath.ref, token);
		
		final Path rootpath = scratch.resolve(absref);
		final Path filepath = rootpath.resolve(refAndPath.path);
		if (Files.isDirectory(rootpath)) {
			return filepath;
		}
		final String absrefSafe = absref.replace("/", "_");
		final Path tf = Files.createTempFile(
				temp, "wsobj." + absrefSafe + ".", ".json.tmp");
		final UObject uo = saveObjectToFile(token, absref, tf);
		final Path enc = Files.createTempFile(
				temp, "encoded." + absrefSafe + ".", ".zip.b64.tmp");
		try (final JsonTokenStream jts = uo.getPlacedStream();) {
			//TODO KBCOMMON JTS should allow getting an inputstream
			jts.close();
			jts.setRoot(Arrays.asList(
					"result", "0", "data", "0", "data", "file"));
			jts.writeJson(enc.toFile());
		}
		Files.delete(tf);
		final Path zip = Files.createTempFile(
				temp, absrefSafe + ".", ".zip.tmp");
		try (final OutputStream os = Files.newOutputStream(zip);
				final InputStream is = new RemoveFirstAndLast(
						new BufferedInputStream(Files.newInputStream(enc)),
						Files.size(enc))) {
			IOUtils.copy(Base64.getDecoder().wrap(is), os);
		}
		Files.delete(enc);
		unzip(rootpath, zip);
		Files.delete(zip);
		return filepath;
	}
	
	private String getAbsoluteRef(final String ref, final AuthToken token)
			throws IOException, ServerException {
		
		final WorkspaceClient ws;
		if (token == null) {
			ws = new WorkspaceClient(wsURL);
		} else {
			try {
				ws = new WorkspaceClient(wsURL, token);
			} catch (UnauthorizedException e) {
				//TODO KBSDK remove UExp from this constructor
				throw new RuntimeException("This is impossible, neat", e);
			}
		}
		
		try {
			final Tuple11<Long, String, String, String, Long, String, Long,
				String, String, Long, Map<String, String>> info =
					ws.getObjectInfoNew(new GetObjectInfoNewParams()
							.withIncludeMetadata(0L)
							.withObjects(Arrays.asList(
									new ObjectSpecification().withRef(ref))))
					.get(0);
			//TODO NOW check correct HTMLFileSet type
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
			final Path tempfile)
			throws IOException, ServerException {
		final JsonClientCaller ws;
		if (token == null) {
			ws = new JsonClientCaller(wsURL);
		} else {
			try {
				ws = new JsonClientCaller(wsURL, token);
			} catch (UnauthorizedException e) {
				//TODO KBCOMMON remove UExp from this constructor
				throw new RuntimeException("This is impossible, neat", e);
			}
		}
		ws.setFileForNextRpcResponse(tempfile.toFile());
		final Map<String, List<Map<String, String>>> arg = new HashMap<>();
		final Map<String, String> obj = new HashMap<>();
		obj.put("ref", absref);
		arg.put("objects", Arrays.asList(obj));
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
		System.out.println(path);
		final String[] s = path.split("/", 4);
		if (s.length != 4) {
			for (int i = 0; i < s.length; i++) {
				System.out.println(s[i]);
			}
			throw new NotFoundException();
		}
		String ref = s[0] + "/" + s[1];
		if (!"-".equals(s[2])) {
			ref += "/" + s[2];
		}
		return new RefAndPath(ref, Paths.get(s[3]));
	}

	private void handle404(final HttpServletRequest request,
			final HttpServletResponse response) throws IOException {
		logthis(request.getRequestURI() + " 404 " +
				request.getHeader(USER_AGENT));
		response.sendError(404);
	}
	
	
	private void logHeaders(final HttpServletRequest req) {
		final String xFF = req.getHeader(X_FORWARDED_FOR);
		if (xFF != null && !xFF.isEmpty()) {
			logthis(X_FORWARDED_FOR + ": " + xFF);
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
