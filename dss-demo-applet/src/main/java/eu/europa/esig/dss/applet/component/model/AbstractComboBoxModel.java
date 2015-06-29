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
package eu.europa.esig.dss.applet.component.model;

import java.util.ArrayList;
import java.util.List;

import javax.swing.ComboBoxModel;
import javax.swing.event.ListDataListener;

/**
 * This abstract class contains the common aspect of ComboBoxModel (listeners).
 * 
 *
 *
 */

public abstract class AbstractComboBoxModel implements ComboBoxModel {

    private List<ListDataListener> listeners = new ArrayList<ListDataListener>();

    protected abstract List<?> getElements();

    private Object selectedElement;

    @Override
    public int getSize() {
        return getElements().size();
    }

    @Override
    public Object getElementAt(int index) {
        return getElements().get(index);
    }

    @Override
    public void addListDataListener(ListDataListener l) {
        listeners.add(l);
    }

    @Override
    public void removeListDataListener(ListDataListener l) {
        listeners.remove(l);
    }

    @Override
    public void setSelectedItem(Object anItem) {
        selectedElement = null;
        for (Object o : getElements()) {
            if (o != null && o.equals(anItem)) {
                selectedElement = anItem;
            }
        }
    }

    @Override
    public Object getSelectedItem() {
        if (selectedElement != null) {
            for (Object o : getElements()) {
                if (selectedElement.equals(o)) {
                    return selectedElement;
                }
            }
        }
        return null;
    }


}
