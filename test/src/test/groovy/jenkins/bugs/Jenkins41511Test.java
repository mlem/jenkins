package jenkins.bugs;

import jenkins.model.JenkinsImpl;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import hudson.security.HudsonPrivateSecurityRealm;
import jenkins.model.Jenkins;

public class Jenkins41511Test {

    @BeforeClass
    public static void setUpClass() {
        System.setProperty(JenkinsImpl.class.getName()+".slaveAgentPort", "10000");
        System.setProperty(JenkinsImpl.class.getName()+".slaveAgentPortEnforce", "true");
    }

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void configRoundTrip() throws Exception {
        Jenkins.getInstance().setSecurityRealm(new HudsonPrivateSecurityRealm(true, false, null));
        j.submit(j.createWebClient().goTo("configureSecurity").getFormByName("config"));
    }
}
