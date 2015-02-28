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
package eu.europa.ec.markt.dss.applet.view.extension;

import java.awt.Container;

import javax.swing.JLabel;
import javax.swing.JPanel;

import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

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
public class FinishView extends WizardView<ExtendSignatureModel, ExtensionWizardController> {

    private final JLabel message;

    /**
     * 
     * The default constructor for FinishView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public FinishView(final AppletCore core, final ExtensionWizardController controller, final ExtendSignatureModel model) {
        super(core, controller, model);
        message = ComponentFactory.createLabel(ResourceUtils.getI18n("SIGNED_FILE_SAVED"), ComponentFactory.iconSuccess());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final JPanel panel = ComponentFactory.createPanel();
        panel.add(message);
        return panel;
    }

}
