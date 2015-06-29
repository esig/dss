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
package eu.europa.esig.dss.applet.model;

import java.io.File;

import com.jgoodies.binding.beans.Model;

import eu.europa.esig.dss.validation.model.ValidationPolicy;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 */
@SuppressWarnings("serial")
public class ValidationPolicyModel extends Model {

    public static final String PROPERTY_EDIT_DEAFULT_POLICY = "editDefaultPolicy";
    private boolean editDefaultPolicy = true;

    public static final String PROPERTY_SELECTED_FILE = "selectedFile";
    private File selectedFile;

    public static final String PROPERTY_TARGET_FILE = "targetedFile";
    private File targetFile;

    public static final String PROPERTY_VALIDATION_POLICY = "validationPolicy";
    private ValidationPolicy validationPolicy;

    /**
     * @return the selectedFile
     */
    public File getSelectedFile() {
        return selectedFile;
    }

    /**
     * @return the targetFile
     */
    public File getTargetFile() {
        return targetFile;
    }


    public boolean isEditDefaultPolicy() {
        return editDefaultPolicy;
    }

    /**
     * @param selectedFile the selectedFile to set
     */
    public void setSelectedFile(final File selectedFile) {
        final File oldValue = this.selectedFile;
        final File newValue = selectedFile;
        this.selectedFile = newValue;
        firePropertyChange(PROPERTY_SELECTED_FILE, oldValue, newValue);
    }


    /**
     * @param targetFile the targetFile to set
     */
    public void setTargetFile(final File targetFile) {
        final File oldValue = this.targetFile;
        final File newValue = targetFile;
        this.targetFile = newValue;
        firePropertyChange(PROPERTY_TARGET_FILE, oldValue, newValue);
    }

    public void setEditDefaultPolicy(final boolean editDefaultPolicy) {
        final boolean oldValue = this.editDefaultPolicy;
        final boolean newValue = editDefaultPolicy;
        this.editDefaultPolicy = editDefaultPolicy;
        firePropertyChange(PROPERTY_EDIT_DEAFULT_POLICY, oldValue, newValue);
    }

    public ValidationPolicy getValidationPolicy() {
        return validationPolicy;
    }

    public void setValidationPolicy(final ValidationPolicy validationPolicy) {
        final ValidationPolicy oldValue = this.validationPolicy;
        final ValidationPolicy newValue = validationPolicy;
        this.validationPolicy = validationPolicy;
        firePropertyChange(PROPERTY_VALIDATION_POLICY, oldValue, newValue);
    }

}
