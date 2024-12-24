/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * Internalization provider
 *
 */
public class I18nProvider {

	private static final Logger LOG = LoggerFactory.getLogger(I18nProvider.class);
	
	private static final String MESSAGES = "dss-messages"; // defined a name of the target file
	
	// Use system locale as default
	private final ResourceBundle bundle;
	
	// a set of possible keys
	private final Set<String> keySet;
	
	/**
	 * Default internationalization constructor
	 * Instantiates a default {@code Locale}
	 */
	public I18nProvider() {
		this(Locale.getDefault());
	}
	
	/**
	 * Returns an instance of {@code I18nProvider}
	 * 
	 * @param locale {@link Locale} language/location to use
	 */
	public I18nProvider(Locale locale) {
		this.bundle = ResourceBundle.getBundle(MESSAGES, locale);
		this.keySet = bundle.keySet();
	}
	
	/**
	 * Extracts an {@code I18nMessage} by its key
	 * 
	 * @param messageTag {@link MessageTag} key of the message to get value for
	 * @param args an array of optional parameters
	 * @return {@link String} message value
	 */
	public String getMessage(MessageTag messageTag, Object... args) {
		if (messageTag == null) {
			throw new IllegalArgumentException("messageTag cannot be null!");
			
		} else if (keySet.contains(messageTag.getId())) {
			String patternString = bundle.getString(messageTag.getId());
			return MessageFormat.format(patternString, getArgs(args));
			
		} else {
			// in case if a value for the message tag does not exist
			LOG.warn("A value for the MessageTag [{}] not defined!", messageTag.getId());
			return messageTag.getId();
		}
	}

	/** Allows nested MessageTags */
	private Object[] getArgs(Object[] args) {
		Object[] translated = null;
		if (args != null) {
			translated = args.clone();
			for (int i = 0; i < args.length; ++i) {
				if (args[i] instanceof MessageTag) {
					translated[i] = getMessage((MessageTag) args[i]);
				}
			}
		}
		return translated;
	}
	
}
