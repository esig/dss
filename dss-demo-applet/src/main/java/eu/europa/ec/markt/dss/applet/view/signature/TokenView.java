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

package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.Container;

import javax.swing.JRadioButton;

import com.jgoodies.binding.PresentationModel;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.MOCCAAdapter;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

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
public class TokenView extends WizardView<SignatureModel, SignatureWizardController> {

    private static final String I18N_TOKEN_PKCS11 = ResourceUtils.getI18n("PKCS11");
    private static final String I18N_TOKEN_PKCS12 = ResourceUtils.getI18n("PKCS12");
    private static final String I18N_TOKEN_MSCAPI = ResourceUtils.getI18n("MSCAPI");
    private static final String I18N_TOKEN_MOCCA = ResourceUtils.getI18n("MOCCA");

    private final JRadioButton pkcs11Button;
    private final JRadioButton pkcs12Button;
    private final JRadioButton msCapiButton;
    private final JRadioButton moccaButton;

    private final PresentationModel<SignatureModel> presentationModel;

    /**
     * 
     * The default constructor for TokenView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public TokenView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);

        presentationModel = new PresentationModel<SignatureModel>(getModel());

        final ValueModel tokenValue = presentationModel.getModel(SignatureModel.PROPERTY_TOKEN_TYPE);

        pkcs11Button = ComponentFactory.createRadioButton(I18N_TOKEN_PKCS11, tokenValue, SignatureTokenType.PKCS11);
        pkcs12Button = ComponentFactory.createRadioButton(I18N_TOKEN_PKCS12, tokenValue, SignatureTokenType.PKCS12);
        msCapiButton = ComponentFactory.createRadioButton(I18N_TOKEN_MSCAPI, tokenValue, SignatureTokenType.MSCAPI);
        moccaButton = ComponentFactory.createRadioButton(I18N_TOKEN_MOCCA, tokenValue, SignatureTokenType.MOCCA);

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        final String[] colSpecs = new String[] { "5dlu", "pref", "5dlu", "pref:grow", "5dlu" };
        final String[] rowSpecs = new String[] { "5dlu", "pref", "5dlu", "pref", "5dlu", "pref", "5dlu", "pref", "5dlu", "pref", "5dlu" };

        final PanelBuilder builder = ComponentFactory.createBuilder(colSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(ResourceUtils.getI18n("TOKEN_API"), cc.xyw(2, 2, 3));
        builder.add(pkcs11Button, cc.xy(2, 4));
        builder.add(pkcs12Button, cc.xy(2, 6));
        builder.add(msCapiButton, cc.xy(2, 8));
        if (new MOCCAAdapter().isMOCCAAvailable()) {
            builder.add(moccaButton, cc.xy(2, 10));
        }

        return ComponentFactory.createPanel(builder);
    }
}
