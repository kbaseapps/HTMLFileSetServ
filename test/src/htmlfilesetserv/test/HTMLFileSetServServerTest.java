package htmlfilesetserv.test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import junit.framework.Assert;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;


import htmlfilesetserv.HTMLFileSetHTTPServer;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthService;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.test.TestCommon;

public class HTMLFileSetServServerTest {
	
	private static AuthToken token = null;
	private static Map<String, String> config = null;
	
	private static Path SCRATCH;
	private static HTMLFileSetHTTPServer HTML_SERVER;
	
	@BeforeClass
	public static void init() throws Exception {
		//TODO TEST AUTH make configurable?
		token = AuthService.validateToken(System.getenv("KB_AUTH_TOKEN"));
		//TODO ZZEXTERNAL BLOCKER TEST need another user
		
		String configFilePath = System.getenv("KB_DEPLOYMENT_CONFIG");
		File deploy = new File(configFilePath);
		Ini ini = new Ini(deploy);
		config = ini.get("HTMLFileSetServ");
		SCRATCH = Paths.get(config.get("scratch"));
		Path testCfg = SCRATCH.resolve("../test.cfg");
		Properties p = new Properties();
		p.load(Files.newInputStream(testCfg));
		System.out.println(p);
		
		// These lines are necessary because we don't want to start linux
		// syslog bridge service
		JsonServerSyslog.setStaticUseSyslog(false);
		JsonServerSyslog.setStaticMlogFile(
				new File(config.get("scratch"), "test.log").getAbsolutePath());
		
		final String wsURL = config.get("workspace-url");

		HTML_SERVER = startupHTMLServer(wsURL);
		int htmlport = HTML_SERVER.getServerPort();
		System.out.println("Started html server on port " + htmlport);
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
	}

	@Test
	public void testYourMethod() throws Exception {
		// Prepare test objects in workspace if needed using 
		// wsClient.saveObjects(new SaveObjectsParams().withWorkspace(getWsName()).withObjects(Arrays.asList(
		//         new ObjectSaveData().withType("SomeModule.SomeType").withName(objName).withData(new UObject(obj)))));
		//
		// Run your method by
		// YourRetType ret = impl.yourMethod(params, token);
		//
		// Check returned data with
		// Assert.assertEquals(..., ret.getSomeProperty());
		// ... or other JUnit methods.
	}
}
