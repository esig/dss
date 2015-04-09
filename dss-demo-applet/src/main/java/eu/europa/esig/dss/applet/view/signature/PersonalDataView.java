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
package eu.europa.esig.dss.applet.view.signature;

import java.awt.Container;
import java.beans.PropertyChangeEvent;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.jgoodies.binding.PresentationModel;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.signature.SignatureWizardController;

/**
 * TODO
 * 
 *
 *
 * 
 *
 *
 */
public class PersonalDataView extends WizardView<SignatureModel, SignatureWizardController> {

    private static final String I18N_OID = ResourceUtils.getI18n("OID");
    private static final String I18N_HASH_ALGORITHM = ResourceUtils.getI18n("HASH_ALGORITHM");
    private static final String I18N_HASH_VALUE = ResourceUtils.getI18n("HASH_VALUE");
    private static final String I18N_SIGNATURE_POLICY = ResourceUtils.getI18n("SIGNATURE_POLICY");
    private static final String I18N_CLAIMED_ROLE = ResourceUtils.getI18n("CLAIMED_ROLE");
	private static final String I18N_TSL_SIGNATURE = ResourceUtils.getI18n("TSL_SIGNATURE");

    private final JCheckBox claimedCheckBox;
    private final JCheckBox policyCheckBox;
	private final JCheckBox tslSignatureCheckBox;

    private final JPanel explicitPanel;
    private final JTextField claimedRoleInput;
    private final JTextField policyIDInput;
    private final JTextField policyAlgoInput;
    private final JTextField policyHashValueInput;

    private final PresentationModel<SignatureModel> presentationModel;

    /**
     * The default constructor for PersonalDataView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public PersonalDataView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);

        this.presentationModel = new PresentationModel<SignatureModel>(getModel());

        // Initialize value models

        final ValueModel claimedCheck = presentationModel.getModel(SignatureModel.PROPERTY_CLAIMED_CHECK);
        final ValueModel claimedRole = presentationModel.getModel(SignatureModel.PROPERTY_CLAIMED_ROLE);
		final ValueModel tslSignatureCheck = presentationModel.getModel(SignatureModel.PROPERTY_TSL_SIGNATURE_CHECK);
        final ValueModel policyCheck = presentationModel.getModel(SignatureModel.PROPERTY_SIGNATURE_POLICY_CHECK);
        final ValueModel policyID = presentationModel.getModel(SignatureModel.PROPERTY_POLICY_ID);
        final ValueModel policyAlgo = presentationModel.getModel(SignatureModel.PROPERTY_POLICY_ALGO);
        final ValueModel policyHashValue = presentationModel.getModel(SignatureModel.PROPERTY_POLICY_VALUE);

        // Initialize components
        claimedCheckBox = ComponentFactory.createCheckBox(claimedCheck, I18N_CLAIMED_ROLE);
		tslSignatureCheckBox = ComponentFactory.createCheckBox(tslSignatureCheck, I18N_TSL_SIGNATURE);
        policyCheckBox = ComponentFactory.createCheckBox(policyCheck, I18N_SIGNATURE_POLICY);

        explicitPanel = ComponentFactory.createPanel();

        policyIDInput = ComponentFactory.createTextField(policyID, false);
        policyAlgoInput = ComponentFactory.createTextField(policyAlgo, false);
        policyHashValueInput = ComponentFactory.createTextField(policyHashValue, false);

        claimedRoleInput = ComponentFactory.createTextField(claimedRole, false);

    }

    private JPanel doExplicitLayout() {

        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref:grow, 5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout, explicitPanel);
        final CellConstraints cc = new CellConstraints();

        builder.add(ComponentFactory.createLabel(I18N_OID), cc.xy(2, 2));
        builder.add(policyIDInput, cc.xy(4, 2));
        builder.add(ComponentFactory.createLabel(I18N_HASH_ALGORITHM), cc.xy(2, 4));
        builder.add(policyAlgoInput, cc.xy(4, 4));
        builder.add(ComponentFactory.createLabel(I18N_HASH_VALUE), cc.xy(2, 6));
        builder.add(policyHashValueInput, cc.xy(4, 6));

        return ComponentFactory.createPanel(builder);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        updateDisplay();
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.esig.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref:grow, 5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Additional data for signature meta-data", cc.xyw(2, 2, 3));
        builder.add(claimedCheckBox, cc.xy(2, 4));
        builder.add(claimedRoleInput, cc.xy(4, 4));
		builder.add(tslSignatureCheckBox, cc.xy(2, 6));
        builder.add(policyCheckBox, cc.xy(2, 8));
        builder.add(doExplicitLayout(), cc.xy(4, 8));

        return ComponentFactory.createPanel(builder);
    }

    /**
     * 
     */
    private void updateDisplay() {
        final SignatureModel model = getModel();
        claimedRoleInput.setEnabled(model.isClaimedCheck());
        explicitPanel.setVisible(model.isSignaturePolicyCheck());
        policyCheckBox.setVisible(model.isSignaturePolicyVisible());
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView#wizardModelChange(java.beans.PropertyChangeEvent
     * )
     */
    @Override
    public void wizardModelChange(final PropertyChangeEvent evt) {
        updateDisplay();
    }

}
