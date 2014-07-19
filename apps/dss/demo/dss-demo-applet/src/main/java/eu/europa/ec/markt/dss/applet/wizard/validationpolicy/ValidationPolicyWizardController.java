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
package eu.europa.ec.markt.dss.applet.wizard.validationpolicy;

import java.util.HashMap;
import java.util.Map;

import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.applet.view.validationpolicy.EditView;
import eu.europa.ec.markt.dss.applet.view.validationpolicy.FileView;
import eu.europa.ec.markt.dss.applet.view.validationpolicy.FinishView;
import eu.europa.ec.markt.dss.applet.view.validationpolicy.SaveView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;

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
public class ValidationPolicyWizardController extends WizardController<ValidationPolicyModel> {

    private FileView fileView;
    private EditView editView;
    private SaveView saveView;
    private FinishView finishView;


    /**
     *
     * The default constructor for ValidationPolicyWizardController.
     *
     * @param core
     * @param model
     */
    public ValidationPolicyWizardController(final DSSAppletCore core, final ValidationPolicyModel model) {
        super(core, model);
    }

    @Override
    protected void doCancel() {
        getCore().getController(ActivityController.class).display();
    }

    @Override
    protected Class<? extends WizardStep<ValidationPolicyModel, ? extends WizardController<ValidationPolicyModel>>> doStart() {
        return FileStep.class;
    }

    @Override
    protected void registerViews() {
        this.fileView = new FileView(getCore(), this, getModel());
        this.editView = new EditView(getCore(), this, getModel());
        this.saveView = new SaveView(getCore(), this, getModel());
        this.finishView = new FinishView(getCore(), this, getModel());
    }

    @Override
    protected Map<Class<? extends WizardStep<ValidationPolicyModel, ? extends WizardController<ValidationPolicyModel>>>, ? extends WizardStep<ValidationPolicyModel, ? extends WizardController<ValidationPolicyModel>>> registerWizardStep() {
        final Map steps = new HashMap();
        steps.put(FileStep.class, new FileStep(getModel(), fileView, this));
        steps.put(EditStep.class, new EditStep(getModel(), editView, this));
        steps.put(SaveStep.class, new SaveStep(getModel(), saveView, this));
        steps.put(FinishStep.class, new FinishStep(getModel(), finishView, this));
        return steps;
    }

}
