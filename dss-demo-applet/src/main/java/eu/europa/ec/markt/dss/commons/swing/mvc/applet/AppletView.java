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

package eu.europa.ec.markt.dss.commons.swing.mvc.applet;

import java.awt.*;

import eu.europa.ec.markt.dss.applet.util.ComponentFactory;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @param <M>  model
 * @param <C>  controller
 * @param <JC> Component
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class AppletView<M, C extends AppletController<? extends AppletCore, M>> {

    protected static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AppletView.class);

    private final AppletCore core;
    private final M model;
    private final C controller;

    /**
     * The default constructor for AbstractView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public AppletView(final AppletCore core, final C controller, final M model) {
        this.core = core;
        this.controller = controller;
        this.model = model;
    }

    /**
     * @return the controller
     */
    public C getController() {
        return controller;
    }

    /**
     * @return
     */
    protected AppletCore getCore() {
        return core;
    }

    /**
     * @return the model
     */
    public M getModel() {
        return model;
    }

    /**
     * @return
     */
    protected abstract Container layout();

    /**
     *
     */
    public void show() {

        final Container content = layout();
        ComponentFactory.updateDisplay(getCore(), content);
    }

}
