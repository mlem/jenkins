package jenkins.model;

import com.google.inject.Injector;
import hudson.*;
import hudson.cli.declarative.CLIMethod;
import hudson.cli.declarative.CLIResolver;
import hudson.init.InitMilestone;
import hudson.lifecycle.Lifecycle;
import hudson.lifecycle.RestartNotSupportedException;
import hudson.logging.LogRecorderManager;
import hudson.markup.MarkupFormatter;
import hudson.model.*;
import hudson.model.labels.LabelAtom;
import hudson.model.listeners.SCMListener;
import hudson.scm.RepositoryBrowser;
import hudson.scm.SCM;
import hudson.security.AuthorizationStrategy;
import hudson.security.FederatedLoginService;
import hudson.security.SecurityMode;
import hudson.security.SecurityRealm;
import hudson.security.csrf.CrumbIssuer;
import hudson.slaves.Cloud;
import hudson.slaves.NodeProperty;
import hudson.slaves.NodePropertyDescriptor;
import hudson.slaves.RetentionStrategy;
import hudson.tasks.BuildWrapper;
import hudson.tasks.Builder;
import hudson.tasks.Publisher;
import hudson.triggers.TriggerDescriptor;
import hudson.util.*;
import hudson.views.MyViewsTabBar;
import hudson.views.ViewsTabBar;
import hudson.widgets.Widget;
import jenkins.ExtensionRefreshException;
import jenkins.install.InstallState;
import jenkins.install.SetupWizard;
import org.acegisecurity.AccessDeniedException;
import org.jvnet.hudson.reactor.ReactorException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.args4j.Argument;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.framework.adjunct.AdjunctManager;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;

/**
 * Created by martin on 26.04.17.
 */
public interface JenkinsAll {
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

    List<Action> getActions();

    Map<String,TopLevelItem> getItemMap();

    <T> List<T> getItems(Class<T> type);

    <T extends Item> List<T> getAllItems(Class<T> type);

    <T extends Item> Iterable<T> allItems(Class<T> type);

    List<Item> getAllItems();

    Iterable<Item> allItems();

    @Deprecated
    List<Project> getProjects();

    Collection<String> getJobNames();

    Collection<String> getTopLevelItemNames();

    // even if we want to offer this atomic operation, CopyOnWriteArrayList
    // offers no such operation
    void setViews(Collection<View> views) throws IOException;

    void setPrimaryView(View v);

    void setViewsTabBar(ViewsTabBar viewsTabBar);

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

    List<JDK> getJDKs();

    @Restricted(NoExternalUse.class)
    void setJDKs(Collection<? extends JDK> jdks);

    JDK getJDK(String name);

    @CheckForNull
    Node getNode(String name);

    Cloud getCloud(String name);

    @Restricted(NoExternalUse.class)
    Nodes getNodesObject();

    void addNode(Node n) throws IOException;

    void removeNode(@Nonnull Node n) throws IOException;

    boolean updateNode(Node n) throws IOException;

    void setNodes(List<? extends Node> n) throws IOException;

    DescribableList<NodeProperty<?>, NodePropertyDescriptor> getGlobalNodeProperties();

    AdministrativeMonitor getAdministrativeMonitor(String id);

    int getQuietPeriod();

    void setQuietPeriod(Integer quietPeriod) throws IOException;

    int getScmCheckoutRetryCount();

    void setScmCheckoutRetryCount(int scmCheckoutRetryCount) throws IOException;

    @Nullable
    String getRootUrl();

    boolean isRootUrlSecure();

    @Nonnull
    String getRootUrlFromRequest();

    File getBuildDirFor(Job job);

    String getRawWorkspaceDir();

    String getRawBuildsDir();

    @Restricted(NoExternalUse.class)
    void setRawBuildsDir(String buildsDir);

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

    AuthorizationStrategy getAuthorizationStrategy();

    ProjectNamingStrategy getProjectNamingStrategy();

    @Exported
    boolean isQuietingDown();

    boolean isTerminating();

    InitMilestone getInitLevel();

    void setNumExecutors(int n) throws IOException;

    Item getItem(String pathName, ItemGroup context);

    Item getItem(String pathName, Item context);

    <T extends Item> T getItem(String pathName, ItemGroup context, @Nonnull Class<T> type);

    <T extends Item> T getItem(String pathName, Item context, Class<T> type);

    @CheckForNull
    <T extends Item> T getItemByFullName(String fullName, Class<T> type) throws AccessDeniedException;

    @CheckForNull
    Item getItemByFullName(String fullName);

    @CheckForNull
    User getUser(String name);

    TopLevelItem createProject(TopLevelItemDescriptor type, String name) throws IOException;

    void putItem(TopLevelItem item) throws IOException, InterruptedException;

    <T extends TopLevelItem> T createProject(Class<T> type, String name) throws IOException;

    FingerprintMap getFingerprintMap();

    // if no finger print matches, display "not found page".
    Object getFingerprint(String md5sum) throws IOException;

    Fingerprint _getFingerprint(String md5sum) throws IOException;

    void setMode(Node.Mode m) throws IOException;

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

    boolean isSubjectToMandatoryReadPermissionCheck(String restOfPath);

    Collection<String> getUnprotectedRootActions();

    FormValidation doCheckDisplayName(@QueryParameter String displayName,
                                      @QueryParameter String jobName);
}
