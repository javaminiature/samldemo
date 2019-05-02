package com.javaminiature.samldemo.configuration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter implements InitializingBean, DisposableBean {

	private Timer backgroundTaskTimer;
	private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

	@Autowired
	private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;
	
	@Autowired
	private IDPConfiguration idpconfiguration;
	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.httpBasic().authenticationEntryPoint(getSamlEntryPoint());
		http.addFilterBefore(getMetadataGeneratorFilter(), ChannelProcessingFilter.class);
		http.addFilterAfter(getSamlFilter(), BasicAuthenticationFilter.class);
		http.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/saml/**").permitAll()
			.anyRequest().authenticated();

	}

	@Bean
	public WebSSOProfile webSSOprofile() {
		return new WebSSOProfileImpl();
	}

	@Bean
	public SAMLEntryPoint getSamlEntryPoint() {
		SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
		samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
		return samlEntryPoint;
	}

	@Bean
	public WebSSOProfileOptions defaultWebSSOProfileOptions() {
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setIncludeScoping(false);
		return webSSOProfileOptions;
	}

	@Bean
	public MetadataGeneratorFilter getMetadataGeneratorFilter() {
		return new MetadataGeneratorFilter(getMetadataGenerator());
	}

	@Bean
	public MetadataGenerator getMetadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		metadataGenerator.setEntityId("com:javaminiature:sp");
		metadataGenerator.setExtendedMetadata(getExtendedMetadata());
		metadataGenerator.setIncludeDiscoveryExtension(false);
		metadataGenerator.setKeyManager(getJKSKeyManager());
		return metadataGenerator;
	}

	@Bean
	public KeyManager getJKSKeyManager() {
		DefaultResourceLoader loader = new DefaultResourceLoader();
		Resource storeFile = loader.getResource("classpath:/saml/keystore.jks");
		String storePass = "changeit";
		Map<String, String> passwords = new HashMap<String, String>();
		passwords.put("samldemo", "changeit");
		String defaultKey = "samldemo";
		return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
	}

	@Bean
	public ExtendedMetadata getExtendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		// extendedMetadata.setIdpDiscoveryEnabled(true);
		extendedMetadata.setSignMetadata(false);
		extendedMetadata.setEcpEnabled(true);
		return extendedMetadata;
	}

	@Bean
	public FilterChainProxy getSamlFilter() throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
				metadataDisplayFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
				samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()));        
		return new FilterChainProxy(chains);
	}

	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() throws Exception {
        MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
        metadataDisplayFilter.setContextProvider(contextProvider());
        metadataDisplayFilter.setKeyManager(getJKSKeyManager());
        metadataDisplayFilter.setManager(metadata());
        return metadataDisplayFilter;
    }
    
	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOProcessingFilter;
	}

	@Bean
	public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
		SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successRedirectHandler.setDefaultTargetUrl("/home");
		return successRedirectHandler;
	}

	@Bean
	public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
		failureHandler.setUseForward(true);
		failureHandler.setDefaultFailureUrl("/error");
		return failureHandler;
	}

	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException {
		List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
		providers.add(ssoExtendedMetadataProvider());
		return new CachingMetadataManager(providers);
	}

	@Bean
	public ExtendedMetadataDelegate ssoExtendedMetadataProvider() throws MetadataProviderException {
		String idpSSOMetadataURL=idpconfiguration.getMetadata().getUrl();
		HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(this.backgroundTaskTimer, httpClient(),
				idpSSOMetadataURL);
		httpMetadataProvider.setParserPool(parserPool());
		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(httpMetadataProvider,
				getExtendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(true);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		backgroundTaskTimer.purge();
		return extendedMetadataDelegate;		
	}
		
	@Bean
	public HttpClient httpClient() {
		return new HttpClient(this.multiThreadedHttpConnectionManager);
	}

	@Bean(initMethod = "initialize")
	public StaticBasicParserPool parserPool() {
		return new StaticBasicParserPool();
	}

	@Bean(name = "parserPoolHolder")
	public ParserPoolHolder parserPoolHolder() {
		return new ParserPoolHolder();
	}

	public void init() {
		this.backgroundTaskTimer = new Timer(true);
		this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
	}

	public void shutdown() {
		this.backgroundTaskTimer.purge();
		this.backgroundTaskTimer.cancel();
		this.multiThreadedHttpConnectionManager.shutdown();
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		init();

	}

	@Override
	public void destroy() throws Exception {
		shutdown();

	}

	// Initialization of OpenSAML library
	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new SAMLBootstrap();
	}

	@Bean
	public VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	// Bindings
	private ArtifactResolutionProfile artifactResolutionProfile() {
		final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
		artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
		return artifactResolutionProfile;
	}

	@Bean
	public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
		return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
	}

	@Bean
	public HTTPSOAP11Binding soapBinding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(parserPool(), velocityEngine());
	}

	@Bean
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(parserPool());
	}

	@Bean
	public HTTPSOAP11Binding httpSOAP11Binding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPAOS11Binding httpPAOS11Binding() {
		return new HTTPPAOS11Binding(parserPool());
	}

	// Processor
	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		bindings.add(artifactBinding(parserPool(), velocityEngine()));
		bindings.add(httpSOAP11Binding());
		bindings.add(httpPAOS11Binding());
		return new SAMLProcessorImpl(bindings);
	}

	@Bean
	public SAMLDefaultLogger samlLogger() {
		return new SAMLDefaultLogger();
	}

	@Bean
	public SAMLContextProviderImpl contextProvider() {
		SAMLContextProviderImpl scp = new SAMLContextProviderImpl();
		scp.setStorageFactory(new EmptyStorageFactory());
		return scp;
	}

	@Bean
	public SAMLAuthenticationProvider samlAuthenticationProvider() {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
		samlAuthenticationProvider.setForcePrincipalAsString(false);
		return samlAuthenticationProvider;
	}

	/**
	 * 
	 * Sets a custom authentication provider.
	 * 
	 * @param auth
	 *            SecurityBuilder used to create an AuthenticationManager.
	 * @throws Exception
	 */

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(samlAuthenticationProvider());
	}

	// SAML 2.0 WebSSO Assertion Consumer

	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		return new WebSSOProfileConsumerImpl();
	}

	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
		return new WebSSOProfileConsumerHoKImpl();
	}
	
	// Handler for successful logout
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/home");
        successLogoutHandler.setAlwaysUseDefaultTargetUrl(true);
        return successLogoutHandler;
    }
     
    // Logout handler terminating local session
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = 
        		new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }
 
    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler());
    }
     
    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[] { logoutHandler() },
                new LogoutHandler[] { logoutHandler() });
    }
    
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }
}
