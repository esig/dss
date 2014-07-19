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

package eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

import com.jgoodies.binding.beans.Model;

import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @param <M>
 * @param <C>
 */
public abstract class WizardStep<M extends Model, C extends WizardController<M>> {

    private final M model;
    private final WizardView<M, C> view;
    private final C controller;

    /**
     * 
     * The default constructor for DSSWizardStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public WizardStep(final M model, final WizardView<M, C> view, final C controller) {
        this.model = model;
        this.view = view;
        this.controller = controller;
    }

    protected abstract void finish() throws ControllerException;

    /**
     * 
     * @return
     */
    protected abstract Class<? extends WizardStep<M, C>> getBackStep();

    /**
     * @return the controller
     */
    public C getController() {
        return controller;
    }

    /**
     * @return the model
     */
    public M getModel() {
        return model;
    }

    /**
     * 
     * @return
     */
    protected abstract Class<? extends WizardStep<M, C>> getNextStep();

    /**
     * 
     * @return
     */
    protected abstract int getStepProgression();

    /**
     * @return the view
     */
    public WizardView<M, C> getView() {
        return view;
    }

    /**
     * @throws Exception
     * 
     */
    protected abstract void init() throws ControllerException;

    /**
     * 
     * @return
     */
    protected abstract boolean isValid();

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return ReflectionToStringBuilder.reflectionToString(this);
    }

}
