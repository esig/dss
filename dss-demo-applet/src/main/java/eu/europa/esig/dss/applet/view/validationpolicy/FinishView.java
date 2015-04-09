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
package eu.europa.esig.dss.applet.view.validationpolicy;

import java.awt.Container;

import javax.swing.JLabel;
import javax.swing.JPanel;

import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;

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
public class FinishView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

    private final JLabel message;

    /**
     *
     * The default constructor for SignView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public FinishView(final AppletCore core, final ValidationPolicyWizardController controller, final ValidationPolicyModel model) {
        super(core, controller, model);
        message = ComponentFactory.createLabel(ResourceUtils.getI18n("FILE_SAVED"), ComponentFactory.iconSuccess());
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {

    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final JPanel panel = ComponentFactory.createPanel();
        panel.add(message);
        return panel;
    }


}
