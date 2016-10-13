package htmlfilesetserv.test;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import junit.framework.Assert;

import org.ini4j.Ini;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import htmlfilesetserv.HTMLFileSetServServer;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthService;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.RpcContext;
import us.kbase.common.service.UObject;
import us.kbase.workspace.CreateWorkspaceParams;
import us.kbase.workspace.ObjectSaveData;
import us.kbase.workspace.ProvenanceAction;
import us.kbase.workspace.SaveObjectsParams;
import us.kbase.workspace.WorkspaceClient;
import us.kbase.workspace.WorkspaceIdentity;

public class HTMLFileSetServServerTest {
    private static AuthToken token = null;
    private static Map<String, String> config = null;
    private static WorkspaceClient wsClient = null;
    private static String wsName = null;
    private static HTMLFileSetServServer impl = null;
    
    @BeforeClass
    public static void init() throws Exception {
        //TODO TEST AUTH make configurable?
        token = AuthService.validateToken(System.getenv("KB_AUTH_TOKEN"));
        String configFilePath = System.getenv("KB_DEPLOYMENT_CONFIG");
        File deploy = new File(configFilePath);
        Ini ini = new Ini(deploy);
        config = ini.get("HTMLFileSetServ");
        wsClient = new WorkspaceClient(new URL(config.get("workspace-url")), token);
        wsClient.setAuthAllowedForHttp(true);
        // These lines are necessary because we don't want to start linux syslog bridge service
        JsonServerSyslog.setStaticUseSyslog(false);
        JsonServerSyslog.setStaticMlogFile(new File(config.get("scratch"), "test.log").getAbsolutePath());
        impl = new HTMLFileSetServServer();
    }
    
    private static String getWsName() throws Exception {
        if (wsName == null) {
            long suffix = System.currentTimeMillis();
            wsName = "test_HTMLFileSetServ_" + suffix;
            wsClient.createWorkspace(new CreateWorkspaceParams().withWorkspace(wsName));
        }
        return wsName;
    }
    
    private static RpcContext getContext() {
        return new RpcContext().withProvenance(Arrays.asList(new ProvenanceAction()
            .withService("HTMLFileSetServ").withMethod("please_never_use_it_in_production")
            .withMethodParams(new ArrayList<UObject>())));
    }
    
    @AfterClass
    public static void cleanup() {
        if (wsName != null) {
            try {
                wsClient.deleteWorkspace(new WorkspaceIdentity().withWorkspace(wsName));
                System.out.println("Test workspace was deleted");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
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
