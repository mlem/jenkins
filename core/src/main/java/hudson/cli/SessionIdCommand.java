package hudson.cli;

import hudson.Extension;
import jenkins.model.JenkinsImpl;

/**
 * Prints the current session ID number (that changes for every run)
 * to allow clients to reliably wait for a restart.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class SessionIdCommand extends CLICommand {
    @Override
    public String getShortDescription() {
        return Messages.SessionIdCommand_ShortDescription();
    }

    protected int run() {
        stdout.println(JenkinsImpl.SESSION_HASH);
        return 0;
    }
}

