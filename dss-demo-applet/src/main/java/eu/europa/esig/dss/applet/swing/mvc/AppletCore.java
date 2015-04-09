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
package eu.europa.esig.dss.applet.swing.mvc;

import java.applet.Applet;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JApplet;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public abstract class AppletCore extends JApplet {

    private static final long serialVersionUID = 6721104284268815739L;

    protected static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AppletCore.class);

    private final Map<Class<? extends AppletController>, AppletController> controllers = new HashMap<Class<? extends AppletController>, AppletController>();

    private ParameterProvider parameterProvider;

    /**
     * @param controllerClass
     * @return a controller
     */
    @SuppressWarnings("unchecked")
    public <C extends AppletController> C getController(final Class<C> controllerClass) {
        if (!controllers.containsKey(controllerClass)) {
            throw new RuntimeException("The class controller " + controllerClass.getName() + " cannot be find , please register it");
        }
        return (C) controllers.get(controllerClass);
    }

    /**
     * @return the controllers
     */
    public Map<Class<? extends AppletController>, AppletController> getControllers() {
        return controllers;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.applet.Applet#init()
     */
    @Override
    public void init() {
        super.init();
        try {
            for (final UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if (info.getName().equals("Nimbus")) {
                    UIManager.setLookAndFeel(info.getClassName());
                    SwingUtilities.updateComponentTreeUI(this);
                }
            }
        } catch (final Exception exception) {
            LOG.warn("Look and feel Nimbus cannot be installed");
        }
        if (parameterProvider == null) {
            parameterProvider = new AppletParameterProvider(this);
        }
        registerParameters(parameterProvider);
        registerControllers();
        layout(this);
    }

    public void setParameterProvider(ParameterProvider parameterProvider) {
        this.parameterProvider = parameterProvider;
    }

    protected abstract void layout(final AppletCore core);

    protected abstract void registerControllers();

    protected abstract void registerParameters(ParameterProvider parameterProvider);

    public interface ParameterProvider {
        public String getParameter(String parameterName);
    }

    private static class AppletParameterProvider implements ParameterProvider {

        private final Applet applet;

        public AppletParameterProvider(Applet applet) {
            this.applet = applet;
        }

        public String getParameter(String parameterName) {
            return applet.getParameter(parameterName);
        }

    }

}
