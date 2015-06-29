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
package eu.europa.esig.dss.applet.view;

import java.awt.Container;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import com.jgoodies.binding.beans.BeanAdapter;

import eu.europa.esig.dss.applet.controller.DSSAppletController;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.AppletView;

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
public abstract class DSSAppletView<M, C extends DSSAppletController<M>> extends AppletView<M, C> implements PropertyChangeListener {
	/**
	 *
	 * The default constructor for DSSAppletView.
	 *
	 * @param core
	 * @param controller
	 * @param model
	 */
	public DSSAppletView(final AppletCore core, final C controller, final M model) {
		super(core, controller, model);
		final BeanAdapter<M> beanAdapter = new BeanAdapter<M>(model);
		beanAdapter.addBeanPropertyChangeListener(this);
	}

	public void doInit() {
	}

	protected abstract Container doLayout();

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.swing.mvc.AppletView#layout()
	 */
	@Override
	protected Container layout() {
		doInit();
		return doLayout();
	}

	/**
	 *
	 * @param evt
	 */
	public void modelChanged(final PropertyChangeEvent evt) {
	};

	/*
	 * (non-Javadoc)
	 *
	 * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
	 */
	@Override
	public void propertyChange(final PropertyChangeEvent evt) {
		modelChanged(evt);
	}

}
