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
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import com.jgoodies.binding.beans.BeanAdapter;
import com.jgoodies.binding.list.SelectionInList;
import com.jgoodies.binding.value.ValueHolder;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.applet.component.model.AbstractComboBoxModel;
import eu.europa.esig.dss.applet.main.FileType;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.signature.SignatureWizardController;

public class SignatureView extends WizardView<SignatureModel, SignatureWizardController> {

	private final class FormatEventListener implements PropertyChangeListener {
		/*
		 * (non-Javadoc)
		 *
		 * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
		 */
		@Override
		public void propertyChange(final PropertyChangeEvent evt) {
			getModel().setFormat((SignatureForm) evt.getNewValue());
		}
	}

	private final class LevelComboBoxModel extends AbstractComboBoxModel {

		/*
		 * (non-Javadoc)
		 *
		 * @see eu.europa.esig.dss.applet.component.model.AbstractComboBoxModel#getElements()
		 */
		@Override
		protected List<?> getElements() {
			final SignatureModel model = getModel();
			final SignatureForm signatureFormat = model.getFormat();

			final List<String> elements = new ArrayList<String>();
			if (signatureFormat !=null){
				switch (signatureFormat) {
					case PAdES:
						elements.add(SignatureLevel.PAdES_BASELINE_B.toString());
						elements.add(SignatureLevel.PAdES_BASELINE_T.toString());
						elements.add(SignatureLevel.PAdES_BASELINE_LT.toString());
						elements.add(SignatureLevel.PAdES_BASELINE_LTA.toString());
						break;
					case CAdES:
						elements.add(SignatureLevel.CAdES_BASELINE_B.toString());
						elements.add(SignatureLevel.CAdES_BASELINE_T.toString());
						elements.add(SignatureLevel.CAdES_BASELINE_LT.toString());
						elements.add(SignatureLevel.CAdES_BASELINE_LTA.toString());
						break;
					case XAdES:
						elements.add(SignatureLevel.XAdES_BASELINE_B.toString());
						elements.add(SignatureLevel.XAdES_BASELINE_T.toString());
						elements.add(SignatureLevel.XAdES_BASELINE_LT.toString());
						elements.add(SignatureLevel.XAdES_BASELINE_LTA.toString());
						break;
					case ASiC_S:
						elements.add(SignatureLevel.ASiC_S_BASELINE_B.toString());
						elements.add(SignatureLevel.ASiC_S_BASELINE_T.toString());
						elements.add(SignatureLevel.ASiC_S_BASELINE_LT.toString());
						break;
					case ASiC_E:
						elements.add(SignatureLevel.ASiC_E_BASELINE_B.toString());
						elements.add(SignatureLevel.ASiC_E_BASELINE_T.toString());
						elements.add(SignatureLevel.ASiC_E_BASELINE_LT.toString());
						break;
					default:
						break;
				}
			}

			return elements;

		}
	}

	private final class PackagingEventListener implements PropertyChangeListener {
		/*
		 * (non-Javadoc)
		 *
		 * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
		 */
		@Override
		public void propertyChange(final PropertyChangeEvent evt) {
			getModel().setPackaging((SignaturePackaging) evt.getNewValue());
		}

	}

	private static final String I18N_ENVELOPING = ResourceUtils.getI18n("ENVELOPING");
	private static final String I18N_ENVELOPED = ResourceUtils.getI18n("ENVELOPED");
	private static final String I18N_DETACHED = ResourceUtils.getI18n("DETACHED");

	private final JRadioButton cadesButton;
	private final JRadioButton xadesButton;
	private final JRadioButton padesButton;
	private final JRadioButton asicsButton;
	private final JRadioButton asiceButton;
	private final JRadioButton envelopingButton;
	private final JRadioButton envelopedButton;
	private final JRadioButton detachedButton;
	private final JComboBox levelComboBox;

	private final ValueHolder formatValueHolder;
	private final ValueHolder packagingValueHolder;
	private final ValueModel levelValue;

	/**
	 * The default constructor for SignatureView.
	 *
	 * @param core
	 * @param controller
	 * @param model
	 */
	public SignatureView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
		super(core, controller, model);

		final BeanAdapter<SignatureModel> beanAdapter = new BeanAdapter<SignatureModel>(model);

		formatValueHolder = new ValueHolder(model.getFormat());
		formatValueHolder.addPropertyChangeListener(new FormatEventListener());

		cadesButton = ComponentFactory.createRadioButton(SignatureForm.CAdES.name(), formatValueHolder, SignatureForm.CAdES);
		xadesButton = ComponentFactory.createRadioButton(SignatureForm.XAdES.name(), formatValueHolder, SignatureForm.XAdES);
		padesButton = ComponentFactory.createRadioButton(SignatureForm.PAdES.name(), formatValueHolder, SignatureForm.PAdES);
		asicsButton = ComponentFactory.createRadioButton(SignatureForm.ASiC_S.getReadable(), formatValueHolder, SignatureForm.ASiC_S);
		asiceButton = ComponentFactory.createRadioButton(SignatureForm.ASiC_E.getReadable(), formatValueHolder, SignatureForm.ASiC_E);

		packagingValueHolder = new ValueHolder(model.getPackaging());
		packagingValueHolder.addPropertyChangeListener(new PackagingEventListener());

		envelopingButton = ComponentFactory.createRadioButton(I18N_ENVELOPING, packagingValueHolder, SignaturePackaging.ENVELOPING);
		envelopedButton = ComponentFactory.createRadioButton(I18N_ENVELOPED, packagingValueHolder, SignaturePackaging.ENVELOPED);
		detachedButton = ComponentFactory.createRadioButton(I18N_DETACHED, packagingValueHolder, SignaturePackaging.DETACHED);

		levelValue = beanAdapter.getValueModel(SignatureModel.PROPERTY_LEVEL);
		final SelectionInList<String> levels = new SelectionInList<String>(new LevelComboBoxModel(), levelValue);
		levelComboBox = ComponentFactory.createComboBox(levels);
	}

	private JPanel doFormatLayout() {
		return ComponentFactory.createPanel(cadesButton, xadesButton, padesButton, asicsButton, asiceButton);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
	 */
	@Override
	public void doInit() {
		final SignatureModel model = getModel();
		final SignaturePackaging packaging = model.getPackaging();
		final SignatureForm format = model.getFormat();
		final FileType fileType = model.getFileType();

		padesButton.setEnabled(FileType.PDF == fileType);

		formatValueHolder.setValue(format);
		packagingValueHolder.setValue(packaging);
		levelValue.setValue(model.getLevel());

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.view.DSSAppletView#doInit()
	 */
	@Override
	protected Container doLayout() {

		final JPanel formatPanel = doFormatLayout();
		final JPanel packagingPanel = doPackagingLayout();
		final JPanel levelPanel = doLevelLayout();

		final FormLayout layout = new FormLayout("5dlu,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu,pref, 5dlu,pref, 5dlu, pref, 5dlu");
		final PanelBuilder builder = ComponentFactory.createBuilder(layout);
		final CellConstraints cc = new CellConstraints();
		builder.addSeparator(ResourceUtils.getI18n("SIGNATURE_FORMAT"), cc.xyw(2, 2, 1));
		builder.add(formatPanel, cc.xyw(2, 4, 1));
		builder.addSeparator(ResourceUtils.getI18n("PACKAGING"), cc.xyw(2, 6, 1));
		builder.add(packagingPanel, cc.xyw(2, 8, 1));
		builder.addSeparator(ResourceUtils.getI18n("LEVEL"), cc.xyw(2, 10, 1));
		builder.add(levelPanel, cc.xy(2, 12));
		return ComponentFactory.createPanel(builder);
	}

	private JPanel doLevelLayout() {
		final FormLayout layout = new FormLayout("5dlu, fill:default:grow, 5dlu", "5dlu, pref, 5dlu");
		final PanelBuilder builder = ComponentFactory.createBuilder(layout);
		final CellConstraints cc = new CellConstraints();
		builder.add(levelComboBox, cc.xy(2, 2));
		return ComponentFactory.createPanel(builder);
	}

	private JPanel doPackagingLayout() {
		return ComponentFactory.createPanel(envelopingButton, envelopedButton, detachedButton);
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
		if (SignatureModel.PROPERTY_FORMAT.equals(evt.getPropertyName())) {

			final SignatureForm format = getModel().getFormat();
			if (format != null) {
				switch (format) {
					case CAdES:
						envelopingButton.setEnabled(true);
						detachedButton.setEnabled(true);
						envelopedButton.setEnabled(false);
						if (envelopedButton.isSelected()) {
							envelopedButton.setSelected(false);
						}
						envelopingButton.doClick();
						break;
					case PAdES:
						envelopingButton.setEnabled(false);
						detachedButton.setEnabled(false);
						envelopedButton.setEnabled(true);
						if (envelopingButton.isSelected() || detachedButton.isSelected()) {
							envelopingButton.setSelected(false);
							detachedButton.setSelected(false);
						}
						envelopedButton.doClick();
						break;
					case XAdES:
						envelopingButton.setEnabled(true);
						detachedButton.setEnabled(true);
						envelopedButton.setEnabled(FileType.XML == getModel().getFileType());

						if (envelopedButton.isSelected()) {
							envelopedButton.setSelected(false);
						}

						envelopingButton.doClick();
						break;
					case ASiC_S:
						envelopingButton.setEnabled(false);
						detachedButton.setEnabled(true);
						envelopedButton.setEnabled(false);
						if (envelopedButton.isSelected() || envelopingButton.isSelected()) {
							envelopingButton.setSelected(false);
							envelopedButton.setSelected(false);
						}
						detachedButton.doClick();
						break;
					case ASiC_E:
						envelopingButton.setEnabled(false);
						detachedButton.setEnabled(true);
						envelopedButton.setEnabled(false);
						if (envelopedButton.isSelected() || envelopingButton.isSelected()) {
							envelopingButton.setSelected(false);
							envelopedButton.setSelected(false);
						}
						detachedButton.doClick();
						break;
					default:
						break;
				}
			}

			levelComboBox.setSelectedIndex(-1);
			if (levelComboBox.getModel().getSize() > 0) {
				levelComboBox.setSelectedIndex(0);
			}
		}

	}
}
