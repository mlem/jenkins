package jenkins.model;

import com.google.inject.Injector;
import com.thoughtworks.xstream.XStream;
import hudson.*;
import hudson.cli.declarative.CLIMethod;
import hudson.cli.declarative.CLIResolver;
import hudson.init.InitMilestone;
import hudson.lifecycle.Lifecycle;
import hudson.lifecycle.RestartNotSupportedException;
import hudson.logging.LogRecorderManager;
import hudson.markup.MarkupFormatter;
import hudson.model.*;
import hudson.model.Messages;
import hudson.model.Queue;
import hudson.model.labels.LabelAtom;
import hudson.model.listeners.SCMListener;
import hudson.remoting.Callable;
import hudson.remoting.VirtualChannel;
import hudson.scm.RepositoryBrowser;
import hudson.scm.SCM;
import hudson.search.SearchIndexBuilder;
import hudson.security.*;
import hudson.security.csrf.CrumbIssuer;
import hudson.slaves.*;
import hudson.tasks.BuildWrapper;
import hudson.tasks.Builder;
import hudson.tasks.Publisher;
import hudson.triggers.TriggerDescriptor;
import hudson.util.*;
import hudson.views.MyViewsTabBar;
import hudson.views.ViewsTabBar;
import hudson.widgets.Widget;
import jenkins.ExtensionRefreshException;
import jenkins.diagnostics.URICheckEncodingMonitor;
import jenkins.install.InstallState;
import jenkins.install.SetupWizard;
import jenkins.util.SystemProperties;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.apache.commons.jelly.JellyException;
import org.jvnet.hudson.reactor.ReactorException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.args4j.Argument;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.framework.adjunct.AdjunctManager;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.*;
import java.util.concurrent.Future;

/**
 * Created by martin on 26.04.17.
 */
public interface Jenkins {
    /**
     * Extension list that {@link #doResources(StaplerRequest, StaplerResponse)} can serve.
     * This set is mutable to allow plugins to add additional extensions.
     */
    Set<String> ALLOWED_RESOURCE_EXTENSIONS = new HashSet<String>(Arrays.asList(
        "js|css|jpeg|jpg|png|gif|html|htm".split("\\|")
    ));
    /**
     * Thread-safe reusable {@link XStream}.
     */
    XStream XSTREAM;
    /**
     * Alias to {@link #XSTREAM} so that one can access additional methods on {@link XStream2} more easily.
     */
    XStream2 XSTREAM2;
    /**
     * The version number before it is "computed" (by a call to computeVersion()).
     * @since 2.0
     */
    @Restricted(NoExternalUse.class)
    String UNCOMPUTED_VERSION = "?";
    PermissionGroup PERMISSIONS = Permission.HUDSON_PERMISSIONS;
    Permission ADMINISTER = Permission.HUDSON_ADMINISTER;
    Permission READ = new Permission(PERMISSIONS,"Read",Messages._Hudson_ReadPermission_Description(),Permission.READ,PermissionScope.JENKINS);
    Permission RUN_SCRIPTS = new Permission(PERMISSIONS, "RunScripts", Messages._Hudson_RunScriptsPermission_Description(), ADMINISTER,PermissionScope.JENKINS);
    /**
     * {@link Authentication} object that represents the anonymous user.
     * Because Acegi creates its own {@link AnonymousAuthenticationToken} instances, the code must not
     * expect the singleton semantics. This is just a convenient instance.
     *
     * @since 1.343
     */
    Authentication ANONYMOUS;

    /**
     * Gets the {@link Jenkins} singleton.
     * {@link #getInstanceOrNull()} provides the unchecked versions of the method.
     * @return {@link Jenkins} instance
     * @throws IllegalStateException {@link Jenkins} has not been started, or was already shut down
     * @since 1.590
     * @deprecated use {@link #getInstance()}
     */
    @Deprecated
    @Nonnull
    static Jenkins getActiveInstance() throws IllegalStateException {
        Jenkins instance = JenkinsImpl.HOLDER.getInstance();
        if (instance == null) {
            throw new IllegalStateException("Jenkins has not been started, or was already shut down");
        }
        return instance;
    }

    /**
     * Gets the {@link Jenkins} singleton.
     * {@link #getActiveInstance()} provides the checked versions of the method.
     * @return The instance. Null if the {@link Jenkins} instance has not been started,
     * or was already shut down
     * @since 1.653
     */
    @CheckForNull
    static Jenkins getInstanceOrNull() {
        return JenkinsImpl.HOLDER.getInstance();
    }

    /**
     * Gets the {@link Jenkins} singleton. In certain rare cases you may have code that is intended to run before
     * Jenkins starts or while Jenkins is being shut-down. For those rare cases use {@link #getInstanceOrNull()}.
     * In other cases you may have code that might end up running on a remote JVM and not on the Jenkins master,
     * for those cases you really should rewrite your code so that when the {@link Callable} is sent over the remoting
     * channel it uses a {@code writeReplace} method or similar to ensure that the {@link Jenkins} class is not being
     * loaded into the remote class loader
     * @return The instance.
     * @throws IllegalStateException {@link Jenkins} has not been started, or was already shut down
     */
    @CLIResolver
    @Nonnull
    static Jenkins getInstance() {
        Jenkins instance = JenkinsImpl.HOLDER.getInstance();
        if (instance == null) {
            if(SystemProperties.getBoolean(Jenkins.class.getName()+".enableExceptionOnNullInstance")) {
                // TODO: remove that second block around 2.20 (that is: ~20 versions to battle test it)
                // See https://github.com/jenkinsci/jenkins/pull/2297#issuecomment-216710150
                throw new IllegalStateException("Jenkins has not been started, or was already shut down");
            }
        }
        return instance;
    }

    /**
     * Check if the given name is suitable as a name
     * for job, view, etc.
     *
     * @throws Failure
     *      if the given name is not good
     */
    static void checkGoodName(String name) throws Failure {
        if(name==null || name.length()==0)
            throw new Failure(hudson.model.Messages.Hudson_NoName());

        if(".".equals(name.trim()))
            throw new Failure(hudson.model.Messages.Jenkins_NotAllowedName("."));
        if("..".equals(name.trim()))
            throw new Failure(hudson.model.Messages.Jenkins_NotAllowedName(".."));
        for( int i=0; i<name.length(); i++ ) {
            char ch = name.charAt(i);
            if(Character.isISOControl(ch)) {
                throw new Failure(hudson.model.Messages.Hudson_ControlCodeNotAllowed(JenkinsImpl.toPrintableName(name)));
            }
            if("?*/\\%!@#$^&|<>[]:;".indexOf(ch)!=-1)
                throw new Failure(Messages.Hudson_UnsafeChar(ch));
        }

        // looks good
    }

    /**
     * Gets the {@link Authentication} object that represents the user
     * associated with the current request.
     */
    static @Nonnull Authentication getAuthentication() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        // on Tomcat while serving the login page, this is null despite the fact
        // that we have filters. Looking at the stack trace, Tomcat doesn't seem to
        // run the request through filters when this is the login request.
        // see http://www.nabble.com/Matrix-authorization-problem-tp14602081p14886312.html
        if(a==null)
            a = ANONYMOUS;
        return a;
    }

    /**
     * @since 1.509.1
     */
    static void _doScript(StaplerRequest req, StaplerResponse rsp, RequestDispatcher view, VirtualChannel channel, ACL acl) throws IOException, ServletException {
        // ability to run arbitrary script is dangerous
        acl.checkPermission(RUN_SCRIPTS);

        String text = req.getParameter("script");
        if (text != null) {
            if (!"POST".equals(req.getMethod())) {
                throw HttpResponses.error(HttpURLConnection.HTTP_BAD_METHOD, "requires POST");
            }

            if (channel == null) {
                throw HttpResponses.error(HttpURLConnection.HTTP_NOT_FOUND, "Node is offline");
            }

            try {
                req.setAttribute("output",
                        RemotingDiagnostics.executeGroovy(text, channel));
            } catch (InterruptedException e) {
                throw new ServletException(e);
            }
        }

        view.forward(req, rsp);
    }

    /**
     * Does not check when system default encoding is "ISO-8859-1".
     */
    @Restricted(NoExternalUse.class)
    @RestrictedSince("2.37")
    @Deprecated
    static boolean isCheckURIEncodingEnabled() {
        return ExtensionList.lookup(URICheckEncodingMonitor.class).get(0).isCheckEnabled();
    }

    /**
     * Shortcut for {@code Jenkins.getInstanceOrNull()?.lookup.get(type)}
     */
    static @CheckForNull <T> T lookup(Class<T> type) {
        Jenkins j = Jenkins.getInstanceOrNull();
        return j != null ? j.lookup.get(type) : null;
    }

    /**
     * Parses {@link #VERSION} into {@link VersionNumber}, or null if it's not parseable as a version number
     * (such as when Jenkins is run with "mvn hudson-dev:run")
     */
    @CheckForNull static VersionNumber getVersion() {
        return JenkinsImpl.toVersion(JenkinsImpl.VERSION);
    }

    /**
     * Get the stored version of Jenkins, as stored by
     * {@link #doConfigSubmit(StaplerRequest, StaplerResponse)}.
     * <p>
     * Parses the version into {@link VersionNumber}, or null if it's not parseable as a version number
     * (such as when Jenkins is run with "mvn hudson-dev:run")
     * @since 2.0
     */
    @Restricted(NoExternalUse.class)
    @CheckForNull static VersionNumber getStoredVersion() {
        return JenkinsImpl.toVersion(Jenkins.getActiveInstance().version);
    }

    @Nonnull
    @Restricted(NoExternalUse.class)
    InstallState getInstallState();

    @Restricted(NoExternalUse.class)
    void setInstallState(@Nonnull InstallState newState);

    TcpSlaveAgentListener getTcpSlaveAgentListener();

    AdjunctManager getAdjuncts(String dummy);

    @Exported
    int getSlaveAgentPort();

    boolean isSlaveAgentPortEnforced();

    void setSlaveAgentPort(int port) throws IOException;

    Set<String> getAgentProtocols();

    void setAgentProtocols(Set<String> protocols);

    void setNodeName(String name);

    String getNodeDescription();

    @Exported
    String getDescription();

    PluginManager getPluginManager();

    UpdateCenter getUpdateCenter();

    boolean isUsageStatisticsCollected();

    void setNoUsageStatistics(Boolean noUsageStatistics) throws IOException;

    View.People getPeople();

    View.AsynchPeople getAsynchPeople();

    @Deprecated
    boolean hasPeople();

    Api getApi();

    @Deprecated
    String getSecretKey();

    @Deprecated
    SecretKey getSecretKeyAsAES128();

    @SuppressWarnings("deprecation")
    String getLegacyInstanceId();

    Descriptor<SCM> getScm(String shortClassName);

    Descriptor<RepositoryBrowser<?>> getRepositoryBrowser(String shortClassName);

    Descriptor<Builder> getBuilder(String shortClassName);

    Descriptor<BuildWrapper> getBuildWrapper(String shortClassName);

    Descriptor<Publisher> getPublisher(String shortClassName);

    TriggerDescriptor getTrigger(String shortClassName);

    Descriptor<RetentionStrategy<?>> getRetentionStrategy(String shortClassName);

    JobPropertyDescriptor getJobProperty(String shortClassName);

    @Deprecated
    ComputerSet getComputer();

    @SuppressWarnings({"unchecked", "rawtypes"}) // too late to fix
    Descriptor getDescriptor(String id);

    Descriptor getDescriptorByName(String id);

    @CheckForNull
    Descriptor getDescriptor(Class<? extends Describable> type);

    Descriptor getDescriptorOrDie(Class<? extends Describable> type);

    <T extends Descriptor> T getDescriptorByType(Class<T> type);

    Descriptor<SecurityRealm> getSecurityRealms(String shortClassName);

    @Deprecated
    CopyOnWriteList<SCMListener> getSCMListeners();

    @CheckForNull
    Plugin getPlugin(String shortName);

    @SuppressWarnings("unchecked")
    @CheckForNull
    <P extends Plugin> P getPlugin(Class<P> clazz);

    <P extends Plugin> List<P> getPlugins(Class<P> clazz);

    String getSystemMessage();

    @Nonnull
    MarkupFormatter getMarkupFormatter();

    void setMarkupFormatter(MarkupFormatter f);

    void setSystemMessage(String message) throws IOException;

    FederatedLoginService getFederatedLoginService(String name);

    List<FederatedLoginService> getFederatedLoginServices();

    Launcher createLauncher(TaskListener listener);

    String getFullName();

    String getFullDisplayName();

    List<Action> getActions();

    @Exported(name="jobs")
    List<TopLevelItem> getItems();

    Map<String,TopLevelItem> getItemMap();

    <T> List<T> getItems(Class<T> type);

    <T extends Item> List<T> getAllItems(Class<T> type);

    <T extends Item> Iterable<T> allItems(Class<T> type);

    List<Item> getAllItems();

    Iterable<Item> allItems();

    @Deprecated
    List<Project> getProjects();

    Collection<String> getJobNames();

    List<Action> getViewActions();

    Collection<String> getTopLevelItemNames();

    View getView(String name);

    @Exported
    Collection<View> getViews();

    void addView(View v) throws IOException;

    // even if we want to offer this atomic operation, CopyOnWriteArrayList
    // offers no such operation
    void setViews(Collection<View> views) throws IOException;

    boolean canDelete(View view);

    void deleteView(View view) throws IOException;

    void onViewRenamed(View view, String oldName, String newName);

    @Exported
    View getPrimaryView();

    void setPrimaryView(View v);

    ViewsTabBar getViewsTabBar();

    void setViewsTabBar(ViewsTabBar viewsTabBar);

    Jenkins getItemGroup();

    MyViewsTabBar getMyViewsTabBar();

    void setMyViewsTabBar(MyViewsTabBar myViewsTabBar);

    boolean isUpgradedFromBefore(VersionNumber v);

    Computer[] getComputers();

    @CLIResolver
    @CheckForNull
    Computer getComputer(@Argument(required = true, metaVar = "NAME", usage = "Node name") @Nonnull String name);

    Label getLabel(String expr);

    @Nullable
    LabelAtom getLabelAtom(@CheckForNull String name);

    Set<Label> getLabels();

    Set<LabelAtom> getLabelAtoms();

    Queue getQueue();

    String getDisplayName();

    List<JDK> getJDKs();

    @Restricted(NoExternalUse.class)
    void setJDKs(Collection<? extends JDK> jdks);

    JDK getJDK(String name);

    @CheckForNull
    Node getNode(String name);

    Cloud getCloud(String name);

    List<Node> getNodes();

    @Restricted(NoExternalUse.class)
    Nodes getNodesObject();

    void addNode(Node n) throws IOException;

    void removeNode(@Nonnull Node n) throws IOException;

    boolean updateNode(Node n) throws IOException;

    void setNodes(List<? extends Node> n) throws IOException;

    DescribableList<NodeProperty<?>, NodePropertyDescriptor> getNodeProperties();

    DescribableList<NodeProperty<?>, NodePropertyDescriptor> getGlobalNodeProperties();

    AdministrativeMonitor getAdministrativeMonitor(String id);

    NodeDescriptor getDescriptor();

    int getQuietPeriod();

    void setQuietPeriod(Integer quietPeriod) throws IOException;

    int getScmCheckoutRetryCount();

    void setScmCheckoutRetryCount(int scmCheckoutRetryCount) throws IOException;

    String getSearchUrl();

    SearchIndexBuilder makeSearchIndex();

    String getUrlChildPrefix();

    @Nullable
    String getRootUrl();

    boolean isRootUrlSecure();

    @Nonnull
    String getRootUrlFromRequest();

    File getRootDir();

    FilePath getWorkspaceFor(TopLevelItem item);

    File getBuildDirFor(Job job);

    String getRawWorkspaceDir();

    String getRawBuildsDir();

    @Restricted(NoExternalUse.class)
    void setRawBuildsDir(String buildsDir);

    @Nonnull
    FilePath getRootPath();

    FilePath createPath(String absolutePath);

    ClockDifference getClockDifference();

    Callable<ClockDifference, IOException> getClockDifferenceCallable();

    LogRecorderManager getLog();

    @Exported
    boolean isUseSecurity();

    boolean isUseProjectNamingStrategy();

    @Exported
    boolean isUseCrumbs();

    SecurityMode getSecurity();

    SecurityRealm getSecurityRealm();

    void setSecurityRealm(SecurityRealm securityRealm);

    void setAuthorizationStrategy(AuthorizationStrategy a);

    boolean isDisableRememberMe();

    void setDisableRememberMe(boolean disableRememberMe);

    void disableSecurity();

    void setProjectNamingStrategy(ProjectNamingStrategy ns);

    Lifecycle getLifecycle();

    Injector getInjector();

    @SuppressWarnings({"unchecked"})
    <T> ExtensionList<T> getExtensionList(Class<T> extensionType);

    ExtensionList getExtensionList(String extensionType) throws ClassNotFoundException;

    @SuppressWarnings({"unchecked"})
    <T extends Describable<T>,D extends Descriptor<T>> DescriptorExtensionList<T,D> getDescriptorList(Class<T> type);

    void refreshExtensions() throws ExtensionRefreshException;

    ACL getACL();

    AuthorizationStrategy getAuthorizationStrategy();

    ProjectNamingStrategy getProjectNamingStrategy();

    @Exported
    boolean isQuietingDown();

    boolean isTerminating();

    InitMilestone getInitLevel();

    void setNumExecutors(int n) throws IOException;

    TopLevelItem getItem(String name) throws AccessDeniedException;

    Item getItem(String pathName, ItemGroup context);

    Item getItem(String pathName, Item context);

    <T extends Item> T getItem(String pathName, ItemGroup context, @Nonnull Class<T> type);

    <T extends Item> T getItem(String pathName, Item context, Class<T> type);

    File getRootDirFor(TopLevelItem child);

    @CheckForNull
    <T extends Item> T getItemByFullName(String fullName, Class<T> type) throws AccessDeniedException;

    @CheckForNull
    Item getItemByFullName(String fullName);

    @CheckForNull
    User getUser(String name);

    TopLevelItem createProject(TopLevelItemDescriptor type, String name) throws IOException;

    TopLevelItem createProject(TopLevelItemDescriptor type, String name, boolean notify) throws IOException;

    void putItem(TopLevelItem item) throws IOException, InterruptedException;

    <T extends TopLevelItem> T createProject(Class<T> type, String name) throws IOException;

    void onRenamed(TopLevelItem job, String oldName, String newName) throws IOException;

    void onDeleted(TopLevelItem item) throws IOException;

    boolean canAdd(TopLevelItem item);

    <I extends TopLevelItem> I add(I item, String name) throws IOException, IllegalArgumentException;

    void remove(TopLevelItem item) throws IOException, IllegalArgumentException;

    FingerprintMap getFingerprintMap();

    // if no finger print matches, display "not found page".
    Object getFingerprint(String md5sum) throws IOException;

    Fingerprint _getFingerprint(String md5sum) throws IOException;

    int getNumExecutors();

    Node.Mode getMode();

    void setMode(Node.Mode m) throws IOException;

    String getLabelString();

    void setLabelString(String label) throws IOException;

    LabelAtom getSelfLabel();

    Computer createComputer();

    void save() throws IOException;

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")
    void cleanUp();

    Object getDynamic(String token);

    void doConfigSubmit(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException, Descriptor.FormException;

    CrumbIssuer getCrumbIssuer();

    void setCrumbIssuer(CrumbIssuer issuer);

    void doTestPost(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @RequirePOST
    void doConfigExecutorsSubmit(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException, Descriptor.FormException;

    @RequirePOST
    void doSubmitDescription(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @RequirePOST // TODO does not seem to work on _either_ overload!
    HttpRedirect doQuietDown() throws IOException;

    @RequirePOST
    HttpRedirect doQuietDown(@QueryParameter boolean block, @QueryParameter int timeout) throws InterruptedException, IOException;

    @RequirePOST // TODO the cancel link needs to be updated accordingly
    HttpRedirect doCancelQuietDown();

    HttpResponse doToggleCollapse() throws ServletException, IOException;

    void doClassicThreadDump(StaplerResponse rsp) throws IOException, ServletException;

    Map<String,Map<String,String>> getAllThreadDumps() throws IOException, InterruptedException;

    @RequirePOST
    TopLevelItem doCreateItem(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    TopLevelItem createProjectFromXML(String name, InputStream xml) throws IOException;

    @SuppressWarnings({"unchecked"})
    <T extends TopLevelItem> T copy(T src, String name) throws IOException;

    // a little more convenient overloading that assumes the caller gives us the right type
    // (or else it will fail with ClassCastException)
    <T extends AbstractProject<?,?>> T copy(T src, String name) throws IOException;

    @RequirePOST
    void doCreateView(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException, Descriptor.FormException;

    void doSecured(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    void doLoginEntry(StaplerRequest req, StaplerResponse rsp) throws IOException;

    void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    Slave.JnlpJar getJnlpJars(String fileName);

    Slave.JnlpJar doJnlpJars(StaplerRequest req);

    @RequirePOST
    HttpResponse doReload() throws IOException;

    void reload() throws IOException, InterruptedException, ReactorException;

    void doDoFingerprintCheck(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("DM_GC")
    @RequirePOST
    void doGc(StaplerResponse rsp) throws IOException;

    void doException();

    ModelObjectWithContextMenu.ContextMenu doContextMenu(StaplerRequest request, StaplerResponse response) throws IOException, JellyException;

    ModelObjectWithContextMenu.ContextMenu doChildrenContextMenu(StaplerRequest request, StaplerResponse response) throws Exception;

    RemotingDiagnostics.HeapDump getHeapDump() throws IOException;

    @RequirePOST
    void doSimulateOutOfMemory() throws IOException;

    DirectoryBrowserSupport doUserContent();

    @CLIMethod(name="restart")
    void doRestart(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException, RestartNotSupportedException;

    @CLIMethod(name="safe-restart")
    HttpResponse doSafeRestart(StaplerRequest req) throws IOException, ServletException, RestartNotSupportedException;

    void restart() throws RestartNotSupportedException;

    void safeRestart() throws RestartNotSupportedException;

    @CLIMethod(name="shutdown")
    @RequirePOST
    void doExit(StaplerRequest req, StaplerResponse rsp) throws IOException;

    @CLIMethod(name="safe-shutdown")
    @RequirePOST
    HttpResponse doSafeExit(StaplerRequest req) throws IOException;

    void doScript(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    void doScriptText(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @RequirePOST
    void doEval(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    void doSignup(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    void doIconSize(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @RequirePOST
    void doFingerprintCleanup(StaplerResponse rsp) throws IOException;

    @RequirePOST
    void doWorkspaceCleanup(StaplerResponse rsp) throws IOException;

    FormValidation doDefaultJDKCheck(StaplerRequest request, @QueryParameter String value);

    FormValidation doCheckViewName(@QueryParameter String value);

    @Deprecated
    FormValidation doViewExistsCheck(@QueryParameter String value);

    void doResources(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException;

    @Restricted(NoExternalUse.class)
    @RestrictedSince("2.37")
    @Deprecated
    FormValidation doCheckURIEncoding(StaplerRequest request) throws IOException;

    void rebuildDependencyGraph();

    Future<DependencyGraph> rebuildDependencyGraphAsync();

    DependencyGraph getDependencyGraph();

    // for Jelly
    List<ManagementLink> getManagementLinks();

    @Restricted(NoExternalUse.class)
    SetupWizard getSetupWizard();

    User getMe();

    List<Widget> getWidgets();

    Object getTarget();

    boolean isSubjectToMandatoryReadPermissionCheck(String restOfPath);

    Collection<String> getUnprotectedRootActions();

    View getStaplerFallback();

    FormValidation doCheckDisplayName(@QueryParameter String displayName,
                                      @QueryParameter String jobName);
}
