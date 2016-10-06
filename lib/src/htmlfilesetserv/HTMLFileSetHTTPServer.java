package htmlfilesetserv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.productivity.java.syslog4j.SyslogIF;

import us.kbase.common.service.JsonClientException;
import us.kbase.common.service.JsonServerServlet;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.RpcInfo;
import us.kbase.common.service.JsonServerSyslog.SyslogOutput;
import us.kbase.workspace.WorkspaceClient;

/** A server for the HTMLFileSet type.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class HTMLFileSetHTTPServer extends HttpServlet {
	
	//TODO NOW TESTS
	//TODO NOW JAVADOC
	
	private final static String SERVICE_NAME = "HTMLFileSetServ";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String USER_AGENT = "User-Agent";
	private static final String CFG_SCRATCH = "scratch";
	private static final String CFG_WS_URL = "workspace-url";
	
	private final Map<String, String> config;
	private final Path scratch;
	private final URL wsURL;
	
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
		Files.createDirectories(this.scratch);
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
		//TODO NOW shut off logger
		final WorkspaceClient ws = new WorkspaceClient(this.wsURL);
		logthis(String.format("Contacted workspace version %s at %s",
				ws.ver(), this.wsURL), true);
		
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
	
		String path = request.getPathInfo();
		//TODO NOW handle workspace stuff
		System.out.println(path);
		if (path == null || path.trim().isEmpty()) { // e.g. /api/v1
			handle404(request, response);
			return;
		}
		if (path.endsWith("/")) { // e.g. /docs/
			path = path + "index.html";
		}
		// the path is already normalized by the framework, so no need to
		// normalize here
		final Path full = Paths.get(scratch.toString() + path);
		System.out.println(full);
		if (!Files.isRegularFile(full)) {
			handle404(request, response);
			return;
		}
		final InputStream is = Files.newInputStream(full);
		try {
			IOUtils.copy(is, response.getOutputStream());
		} catch (IOException ioe) {
			logthis(request.getRequestURI() + " 500 " +
					request.getHeader(USER_AGENT), ioe);
			response.sendError(500);
			return;
		}
		logthis(request.getRequestURI() + " 200 " +
				request.getHeader(USER_AGENT));
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
