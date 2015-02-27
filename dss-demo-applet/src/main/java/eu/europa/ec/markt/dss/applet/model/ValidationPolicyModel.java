/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.applet.model;

import com.jgoodies.binding.beans.Model;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicy;

import java.io.File;

/**
 *
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
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
