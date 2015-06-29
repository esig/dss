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
package eu.europa.esig.dss.applet.swing.mvc.wizard;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

import com.jgoodies.binding.beans.Model;

import eu.europa.esig.dss.applet.swing.mvc.ControllerException;

/**
 * 
 * TODO
 * 
 *
 *
 * 
 *
 *
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
