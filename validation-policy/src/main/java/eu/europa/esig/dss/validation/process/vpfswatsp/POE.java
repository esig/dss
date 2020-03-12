package eu.europa.esig.dss.validation.process.vpfswatsp;

import java.util.Date;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

/**
 * Contains Proof Of Existence for validation objects
 *
 */
public class POE {
	
	private TimestampWrapper timestampWrapper;
	private final Date poeTime;
	
	/**
	 * The constructor to instantiate POE by a timestamp
	 * 
	 * @param timestampWrapper {@link TimestampWrapper}
	 */
	public POE(TimestampWrapper timestampWrapper) {
		Objects.requireNonNull(timestampWrapper, "The timestampWrapper must be defined!");
		this.timestampWrapper = timestampWrapper;
		this.poeTime = timestampWrapper.getProductionTime();
	}
	
	/**
	 * The constructor to instantiate a global POE by a control/validation time
	 * NOTE: the POE will be applied for all tokens
	 * 
	 * @param controlTime {@link Date}
	 */
	public POE(Date controlTime) {
		Objects.requireNonNull(controlTime, "The controlTime must be defined!");
		this.poeTime = controlTime;
	}
	
	/**
	 * Returns time of the POE
	 * 
	 * @return {@link Date}
	 */
	public Date getTime() {
		return poeTime;
	}
	
	/**
	 * Checks if the POE if a POE defined by a timestamp
	 * 
	 * @return true of the POE defined by a timesatmp, false otherwise
	 */
	public boolean isTimestampPoe() {
		return timestampWrapper != null;
	}
	
	/**
	 * Returns id of the timestamp if defined
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return {@link String} timestamp id
	 */
	public String getTimestampId() {
		if (timestampWrapper != null) {
			return timestampWrapper.getId();
		}
		return null;
	}
	
	/**
	 * Returns timestamp type if the POE defined by a timestamp
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return {@link TimestampType}
	 */
	public TimestampType getTimestampType() {
		if (timestampWrapper != null) {
			return timestampWrapper.getType();
		}
		return null;
	}
	
	/**
	 * Returns a list of timestamped objects if the POE defined by a timestamp
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return a list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getTimestampedObjects() {
		if (timestampWrapper != null) {
			return timestampWrapper.getTimestampedObjects();
		}
		return null;
		
	}

}
