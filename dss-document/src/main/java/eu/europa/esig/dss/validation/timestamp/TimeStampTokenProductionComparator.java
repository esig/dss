package eu.europa.esig.dss.validation.timestamp;

import java.io.Serializable;
import java.util.Comparator;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.spi.DSSASN1Utils;

/**
 * The class used to compare production time of {@code TimeStampToken}s
 * Class checks the production time of timestamps and their covered data
 * 
 * The method compare() returns 
 *     -1 if the {@code timeStampTokenOne} was created before {@code timeStampTokenTwo}
 *     0 if TimeStampTokens were created in the same
 *     1 if the {@code timeStampTokenOne} was created after {@code timeStampTokenTwo}
 *     
 */
public class TimeStampTokenProductionComparator implements Comparator<TimeStampToken>, Serializable {

	private static final long serialVersionUID = 4125423970411266861L;

	@Override
	public int compare(TimeStampToken timeStampTokenOne, TimeStampToken timeStampTokenTwo) {
		
		int result = DSSASN1Utils.getTimeStampTokenGenerationTime(timeStampTokenOne).compareTo(DSSASN1Utils.getTimeStampTokenGenerationTime(timeStampTokenTwo));
		if (result == 0) {			
			
			ASN1Sequence atsHashIndexOne = DSSASN1Utils.getAtsHashIndex(timeStampTokenOne.getUnsignedAttributes());
			ASN1Sequence atsHashIndexTwo = DSSASN1Utils.getAtsHashIndex(timeStampTokenTwo.getUnsignedAttributes());

			if (atsHashIndexOne != null && atsHashIndexTwo != null) {
				
				int hashTableSizeOne = getHashTableSize(atsHashIndexOne);
				int hashTableSizeTwo = getHashTableSize(atsHashIndexTwo);
				
				if (hashTableSizeOne < hashTableSizeTwo) {
					result = -1;
				} else if (hashTableSizeOne > hashTableSizeTwo) {
					result = 1;
				}
			}
		}
		return result;
	}
	
	/**
	 * Returns TRUE if {@code timeStampTokenOne} was created after {@code timeStampTokenTwo}
	 * @param timeStampTokenOne {@link TimeStampToken}
	 * @param timeStampTokenTwo {@link TimeStampToken}
	 * @return TRUE if the first {@link TimeStampToken} has been created after the second timestamp, FALSE otherwise
	 */
	public boolean after(TimeStampToken timeStampTokenOne, TimeStampToken timeStampTokenTwo) {
		return compare(timeStampTokenOne, timeStampTokenTwo) == 1;
	}
	
	private int getHashTableSize(ASN1Sequence derSequence) {
		int recordsNumber = 0;
		for (int ii = 0; ii < derSequence.size(); ii++) {
			ASN1Sequence derEncodedSequence = (ASN1Sequence) derSequence.getObjectAt(ii);
			recordsNumber += derEncodedSequence.size();
		}
		return recordsNumber;
	}

}
