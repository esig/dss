package eu.europa.esig.dss.standalone.fx;

import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;

public class TypedToggleGroup<T> extends ToggleGroup {

	private ObjectProperty<T> selectedValueProperty = new SimpleObjectProperty<T>();

	public TypedToggleGroup() {

		this.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {
			@Override
			@SuppressWarnings("unchecked")
			public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
				if (newValue != null) {
					T obj = (T) newValue.getUserData();
					selectedValueProperty.setValue(obj);
				} else {
					selectedValueProperty.setValue(null);
				}
			}
		});

	}

	public ObjectProperty<T> getSelectedValueProperty() {
		return selectedValueProperty;
	}

}
