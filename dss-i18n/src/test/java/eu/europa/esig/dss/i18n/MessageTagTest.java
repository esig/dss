/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.i18n;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class MessageTagTest {
	
	private static I18nProvider i18nProvider;
	
	@BeforeAll
	static void init() {
		i18nProvider = new I18nProvider();
	}
	
	@Test
	void allMessagesPresent() {
		MessageTag[] values = MessageTag.values();
		assertNotNull(values);
		assertTrue(values.length > 0);
		
		for (MessageTag messageTag : values) {
			String message = i18nProvider.getMessage(messageTag);
			assertNotNull(message, "A message property for a MessageTag with id [" + messageTag.getId() + "] is not defined!");
		}
	}
	
	@Test
	void allFRMessagesPresent() {
		MessageTag[] values = MessageTag.values();
		assertNotNull(values);
		assertTrue(values.length > 0);
		
		// all messages that are not defined in the language-related messages_*.properties
		// will be overridden by default values
		I18nProvider i18nFRProvider = new I18nProvider(Locale.FRENCH);
		for (MessageTag messageTag : values) {
			String message = i18nFRProvider.getMessage(messageTag);
			assertNotNull(message, "A message property for a MessageTag with id [" + messageTag.getId() + "] is not defined!");
		}
	}
	
	@Test
	void allMessageTagsPresent() {
		ResourceBundle bundle = ResourceBundle.getBundle("dss-messages", Locale.getDefault());
		Set<String> keySet = bundle.keySet();
		assertNotNull(keySet);
		assertTrue(keySet.size() > 0);
		
		MessageTag[] messageTags = MessageTag.values();
		for (String key : keySet) {
			assertTrue(Arrays.stream(messageTags).anyMatch(tag -> tag.getId().equals(key)), "MessageTag with a key [" + key + "] does not exist!");
		}
	}

}
