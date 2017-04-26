package hudson;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.TextPage;

import jenkins.model.JenkinsImpl;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TcpSlaveAgentListenerTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void headers() throws Exception {
        r.getInstance().setSlaveAgentPort(-1);
        try {
            r.createWebClient().goTo("tcpSlaveAgentListener");
            fail("Should get 404");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getStatusCode(), is(404));
        }
        r.getInstance().setSlaveAgentPort(0);
        Page p = r.createWebClient().goTo("tcpSlaveAgentListener", "text/plain");
        assertThat(p.getWebResponse().getResponseHeaderValue("X-Instance-Identity"), notNullValue());
    }

    @Test
    public void diagnostics() throws Exception {
        r.getInstance().setSlaveAgentPort(0);
        int p = r.jenkins.getTcpSlaveAgentListener().getPort();
        WebClient wc = r.createWebClient();
        TextPage text = (TextPage) wc.getPage("http://localhost:"+p+"/");
        String c = text.getContent();
        assertThat(c,containsString(JenkinsImpl.VERSION));

        try {
            wc.getPage("http://localhost:"+p+"/xxx");
            fail("Expected 404");
        } catch (FailingHttpStatusCodeException e) {
            assertThat(e.getStatusCode(),equalTo(404));
        }
    }
}
