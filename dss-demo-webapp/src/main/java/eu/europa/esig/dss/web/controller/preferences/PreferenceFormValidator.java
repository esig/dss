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
package eu.europa.esig.dss.web.controller.preferences;

import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import eu.europa.esig.dss.web.model.PreferenceForm;
import eu.europa.esig.dss.web.model.PreferenceKey;

/**
 * Validator for PreferenceForm
 */
@Component
public class PreferenceFormValidator implements Validator {

	@Override
	public boolean supports(Class<?> clazz) {
		return clazz.equals(PreferenceForm.class);
	}

	@Override
	public void validate(Object target, Errors errors) {
		PreferenceForm preferenceForm = (PreferenceForm) target;
		if (preferenceForm.getKey().equals(PreferenceKey.DEFAULT_POLICY_URL.toString())) {
			// check that the entered URL is loadable
			final String value = preferenceForm.getValue();
			if (StringUtils.isNotBlank(value)) {
				try {
					IOUtils.toString(new URL(value).openStream());
				} catch (Exception e) {
					errors.rejectValue("value", "url.error");
				}
			}
		}
	}
}
