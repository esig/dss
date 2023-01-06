package com.sun.tools.xjc.addon.xew.config;

import com.sun.tools.xjc.BadCommandLineException;
import com.sun.tools.xjc.Options;
import com.sun.tools.xjc.Plugin;
import com.sun.tools.xjc.addon.xew.config.CommonConfiguration.ConfigurationOption;
import com.sun.tools.xjc.model.CCustomizations;
import com.sun.tools.xjc.model.CPluginCustomization;
import com.sun.tools.xjc.outline.Outline;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Plugin base class that only contains code for plugin initalization and logging.
 *
 * @author <a href="mailto:dkatsubo@epo.org">Dmitry Katsubo</a>
 */
public abstract class AbstractConfigurablePlugin extends Plugin {
	private static final String PLUGIN_NAME = "Xxew";

	private static final QName XEW_QNAME = new QName(
			"http://github.com/jaxb-xew-plugin", "xew");

	protected GlobalConfiguration globalConfiguration = new GlobalConfiguration();

	public static final String COMMONS_LOGGING_LOG_LEVEL_PROPERTY_KEY = "org.apache.commons.logging.simplelog.defaultlog";

	protected Log logger = LogFactory.getLog(getClass());

	private List<String> customizationURIs;

	private Set<QName> customizationElementNames;

	@Override
	public List<String> getCustomizationURIs() {
		if (this.customizationURIs == null) {
			final Collection<QName> customizationElementNames = getCustomizationElementNames();
			this.customizationURIs = new ArrayList<>( customizationElementNames.size());
			for (QName customizationElementName : customizationElementNames) {
				final String namespaceURI = customizationElementName .getNamespaceURI();
				if (!(namespaceURI == null || namespaceURI.length() == 0)) {
					this.customizationURIs.add(namespaceURI);
				}
			}
		}
		return this.customizationURIs;
	}

	@Override
	public boolean isCustomizationTagName(String namespaceURI, String localName) {
		if (this.customizationElementNames == null) {
			this.customizationElementNames = new HashSet<>(getCustomizationElementNames());
		}
		return this.customizationElementNames.contains(new QName(namespaceURI, localName));
	}

	public AbstractConfigurablePlugin() {
		// Reset logger in parent because it should be re-initialized with correct loglevel threshold:
		logger = null;
	}

	@Override
	public String getOptionName() {
		return PLUGIN_NAME;
	}

	@Override
	public String getUsage() {
		return "  " + getArgumentName("")
		            + " Replace collection types with fields having the @XmlElementWrapper and @XmlElement annotations.";
	}

	public Collection<QName> getCustomizationElementNames() {
		return Collections.singletonList(XEW_QNAME);
	}

	private void initLoggerIfNecessary(Options opts) {
		if (logger != null) {
			return;
		}

		// Allow the caller to control the log level by explicitly setting this system variable:
		if (System.getProperty(COMMONS_LOGGING_LOG_LEVEL_PROPERTY_KEY) == null) {
			String logLevel = "WARN";

			if (opts.quiet) {
				logLevel = "FATAL";
			}
			else if (opts.debugMode) {
				logLevel = "DEBUG";
			}
			else if (opts.verbose) {
				logLevel = "INFO";
			}

			System.setProperty(COMMONS_LOGGING_LOG_LEVEL_PROPERTY_KEY, logLevel);
		}

		// The logger needs to be re-created and not taken from cache:
		LogFactory.getFactory().release();

		logger = LogFactory.getLog(getClass());
		globalConfiguration.setLogger(logger);
	}

	protected final void writeSummary(String s) {
		globalConfiguration.writeSummary(s);
	}

	@Override
	public void onActivated(Options opts) {
		initLoggerIfNecessary(opts);
	}

	/**
	 * Generate argument name from option name.
	 */
	private static String getArgumentName(String optionName) {
		return "-" + PLUGIN_NAME + ":" + optionName;
	}

	/**
	 * Parse argument at a given index and apply it to global configuration. Option value may go within the same
	 * argument (separated with equals), or as a following argument.
	 * 
	 * @param args
	 *            list of arguments
	 * @param index
	 *            current index
	 * @param optionName
	 *            the option to match
	 * @return number of arguments processed
	 */
	private int parseArgument(String[] args, int index, ConfigurationOption option) throws BadCommandLineException {
		int recognized = 0;
		String arg = args[index];
		String argumentName = getArgumentName(option.optionName());

		if (arg.startsWith(argumentName)) {
			recognized++;

			try {
				if (arg.length() > argumentName.length()) {
					applyConfigurationOption(globalConfiguration, option, arg.substring(argumentName.length()).trim());
				}
				else {
					applyConfigurationOption(globalConfiguration, option, args[index + 1].trim());
					recognized++;
				}
			}
			catch (ClassNotFoundException e) {
				throw new BadCommandLineException("Invalid class", e);
			}
			catch (IOException e) {
				throw new BadCommandLineException("Failed to read from file", e);
			}
		}

		return recognized;
	}

	/**
	 * Parse and apply plugin configuration options.
	 * 
	 * @return number of consumed argument options
	 */
	@Override
	public int parseArgument(Options opts, String[] args, int i) throws BadCommandLineException {
		initLoggerIfNecessary(opts);

		int recognized = 0;

		String arg = args[i];
		logger.trace("Argument[" + i + "] = " + arg);

		if (arg.equals(getArgumentName(ConfigurationOption.APPLY_PLURAL_FORM.optionName()))) {
			globalConfiguration.setApplyPluralForm(true);
			return 1;
		}
		else if ((recognized = parseArgument(args, i, ConfigurationOption.CONTROL)) == 0
		            && (recognized = parseArgument(args, i, ConfigurationOption.SUMMARY)) == 0
		            && (recognized = parseArgument(args, i, ConfigurationOption.COLLECTION_INTERFACE)) == 0 // longer option name comes first
		            && (recognized = parseArgument(args, i, ConfigurationOption.COLLECTION_IMPLEMENTATION)) == 0
		            && (recognized = parseArgument(args, i, ConfigurationOption.INSTANTIATION_MODE)) == 0) {
			if (arg.startsWith(getArgumentName(""))) {
				throw new BadCommandLineException("Invalid argument " + arg);
			}
		}

		return recognized;
	}

	/**
	 * Try to apply the {@code value} for the given configuration {@code option} to the given {@code configuration}.
	 * Note that depending on configuration level (global, class, property) not every option is applicable (in that case
	 * {@link IllegalArgumentException} is thrown).
	 */
	private static void applyConfigurationOption(CommonConfiguration configuration, ConfigurationOption option,
	            String value) throws IOException, ClassNotFoundException {
		switch (option) {
		case CONTROL:
			if (!(configuration instanceof GlobalConfiguration)) {
				throw new IllegalArgumentException("The option " + option + " is not applicable");
			}
			((GlobalConfiguration) configuration).readControlFile(value);
			break;
		case SUMMARY:
			if (!(configuration instanceof GlobalConfiguration)) {
				throw new IllegalArgumentException("The option " + option + " is not applicable");
			}
			((GlobalConfiguration) configuration).initSummaryWriter(value);
			break;
		case COLLECTION_IMPLEMENTATION:
			configuration.setCollectionImplClass(Class.forName(value));
			break;
		case COLLECTION_INTERFACE:
			configuration.setCollectionInterfaceClass(Class.forName(value));
			break;
		case INSTANTIATION_MODE:
			try {
				configuration.setInstantiationMode(CommonConfiguration.InstantiationMode.valueOf(value.toUpperCase()));
			}
			catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("Unknown instantiation mode \"" + value + "\"");
			}
			break;
		case APPLY_PLURAL_FORM:
			configuration.setApplyPluralForm(Boolean.parseBoolean(value));
			break;
		case ANNOTATE:
			if (!(configuration instanceof ClassConfiguration)) {
				throw new IllegalArgumentException("The option " + option + " is not applicable");
			}
			((ClassConfiguration) configuration).setAnnotatable(Boolean.parseBoolean(value));
			break;
		}
	}

	/**
	 * Clone given configuration and apply settings from global/class/field JAXB customization.
	 */
	protected static <T extends CommonConfiguration> T applyConfigurationFromCustomizations(
	            CommonConfiguration configuration, CCustomizations customizations, boolean cloneClassConfiguration)
	            throws IOException, ClassNotFoundException {
		CPluginCustomization customization = customizations.find(XEW_QNAME.getNamespaceURI(), XEW_QNAME.getLocalPart());

		if (customization == null) {
			if (cloneClassConfiguration) {
				return (T) new ClassConfiguration(configuration);
			}

			return (T) configuration;
		}

		customization.markAsAcknowledged();

		NamedNodeMap attributes = customization.element.getAttributes();

		if (cloneClassConfiguration) {
			configuration = new ClassConfiguration(configuration);
		}

		for (int i = 0; i < attributes.getLength(); i++) {
			Node attribute = attributes.item(i);
			if (attribute.getNamespaceURI() == null) {
				applyConfigurationOption(configuration, ConfigurationOption.byOption(attribute.getNodeName()),
				            attribute.getNodeValue());
			}
		}

		return (T) configuration;
	}

	/**
	 * Implements exception handling.
	 */
	@Override
	public boolean run(Outline outline, Options opt, ErrorHandler errorHandler) throws SAXException {
		try {
			runInternal(outline);

			return true;
		}
		catch (IOException e) {
			logger.error("Failed to read the file", e);
			throw new SAXException(e);
		}
		catch (ClassNotFoundException e) {
			logger.error("Invalid class", e);
			throw new SAXException(e);
		}
	}

	/**
	 * Actual work is done in this method.
	 */
	protected abstract void runInternal(Outline outline) throws ClassNotFoundException, IOException;
}
