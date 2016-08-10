package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent implements Serializable {

	private static final long serialVersionUID = 4258613511229825596L;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private final String status;

	private final Map<String, List<Condition>> qualifiersAndConditions;
	private final List<String> additionalServiceInfoUris;
	private final Date expiredCertsRevocationInfo;

	public ServiceInfoStatus(String status, Map<String, List<Condition>> qualifiersAndConditions, List<String> additionalServiceInfoUris,
			Date expiredCertsRevocationInfo, Date startDate, Date endDate) {
		super(startDate, endDate);
		this.status = status;
		this.qualifiersAndConditions = qualifiersAndConditions;
		this.additionalServiceInfoUris = additionalServiceInfoUris;
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public String getStatus() {
		return status;
	}

	public Map<String, List<Condition>> getQualifiersAndConditions() {
		return qualifiersAndConditions;
	}

	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

	public String toString(final String indent) {
		try {
			final StringBuilder buffer = new StringBuilder();
			buffer.append(indent).append( "Status:\t " ).append( status ).append('\n');
			buffer.append(indent).append( "Valid: \t " ).append(getStartDate()).append(" - ").append(( getEndDate() != null ) ? getEndDate().toString() : "(present)" ).append('\n');
			final String indent1 = indent + "\t";
			final String indent2 = indent1 + "\t";
			if ( qualifiersAndConditions != null && ! qualifiersAndConditions.isEmpty() ) {
				final String indent3 = indent2 + "\t";
				buffer.append(indent1).append("QualifiersAndConditions:\n");
				for ( final Map.Entry<String, List<Condition>> e : qualifiersAndConditions.entrySet() ) {
					buffer.append( indent2 ).append(e.getKey()).append( ":\n" );
					final List<Condition> conditions = e.getValue();
					if ( conditions != null && ! conditions.isEmpty() ) {
						for ( final Condition c : conditions ) {
							buffer.append( c.toString( indent3 ) );
						}
					}
				}
			} else {
				buffer.append(indent1).append("QualifiersAndConditions: (none)\n" );
			}
			if ( additionalServiceInfoUris != null && ! additionalServiceInfoUris.isEmpty() ) {
				buffer.append(indent1).append("AdditionalServiceInfoUris:\n");
				for ( final String uri : additionalServiceInfoUris ) {
					buffer.append( indent2 ).append( uri ).append( '\n' );
				}
			} else {
				buffer.append(indent1).append("AdditionalServiceInfoUris: (none)\n" );
			}
			buffer.append(indent1).append( "ExpiredCertsRevocationInfo: " ).append( ( expiredCertsRevocationInfo != null ) ? expiredCertsRevocationInfo.toString() : "(none)" ).append( '\n' );
			return buffer.toString();
		} catch (Exception e) {
			return super.toString();
		}
	}
}
