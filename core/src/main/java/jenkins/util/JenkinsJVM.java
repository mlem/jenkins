package jenkins.util;

import hudson.WebAppMain;
import javax.servlet.ServletContextEvent;

import jenkins.model.JenkinsImpl;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * A utility class to identify if the current JVM is the one that is running {@link JenkinsImpl}
 *
 * @since 1.653
 */
public class JenkinsJVM {
    /**
     * Flag to identify the JVM running {@link JenkinsImpl}.
     */
    private static boolean jenkinsJVM;

    /**
     * Protect against people instantiating this class.
     */
    @Restricted(NoExternalUse.class)
    protected JenkinsJVM() {
        throw new IllegalAccessError("Utility class");
    }

    /**
     * Identify whether the classloader that loaded this class is the classloader from which {@link JenkinsImpl} has been
     * started.
     *
     * @return {@code true} if this is the classloader on the JVM that started {@link JenkinsImpl} otherwise {@code false}
     */
    public static boolean isJenkinsJVM() {
        return jenkinsJVM;
    }

    /**
     * Verify that the classloader that loaded this class is the classloader from which {@link JenkinsImpl} has been
     * started.
     *
     * @throws IllegalStateException if this is not the classloader on the JVM that started {@link JenkinsImpl}.
     */
    public static void checkJenkinsJVM() {
        if (!isJenkinsJVM()) {
            throw new IllegalStateException("Not running on the Jenkins master JVM");
        }
    }

    /**
     * Verify that the classloader that loaded this class is not the classloader from which {@link JenkinsImpl} has been
     * started.
     *
     * @throws IllegalStateException if this is the classloader on the JVM that started {@link JenkinsImpl}.
     */
    public static void checkNotJenkinsJVM() {
        if (isJenkinsJVM()) {
            throw new IllegalStateException("Running on the Jenkins master JVM");
        }
    }

    /**
     * Used by {@link WebAppMain#contextInitialized(ServletContextEvent)} and
     * {@link WebAppMain#contextDestroyed(ServletContextEvent)} to identify the classloader and JVM which started
     * {@link JenkinsImpl}
     *
     * @param jenkinsJVM {@code true} if and only if this is the classloader and JVM that started {@link JenkinsImpl}.
     */
    @Restricted(NoExternalUse.class)
    protected static void setJenkinsJVM(boolean jenkinsJVM) {
        JenkinsJVM.jenkinsJVM = jenkinsJVM;
    }
}
