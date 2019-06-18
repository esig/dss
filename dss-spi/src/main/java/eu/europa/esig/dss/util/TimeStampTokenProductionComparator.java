package eu.europa.esig.dss.util;

import static eu.europa.esig.dss.OID.id_aa_ATSHashIndex;

import java.util.Comparator;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSASN1Utils;

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
public class TimeStampTokenProductionComparator implements Comparator<TimeStampToken> {

	@Override
	public int compare(TimeStampToken timeStampTokenOne, TimeStampToken timeStampTokenTwo) {
		int result = DSSASN1Utils.getTimeStampTokenGenerationTime(timeStampTokenOne).compareTo(DSSASN1Utils.getTimeStampTokenGenerationTime(timeStampTokenTwo));
		
		if (result == 0) {
			AttributeTable unsignedAttributesOne = timeStampTokenOne.getUnsignedAttributes();
			AttributeTable unsignedAttributesTwo = timeStampTokenTwo.getUnsignedAttributes();
			
			if (unsignedAttributesOne != null && unsignedAttributesTwo != null) {
				ASN1Set asn1SetOne = DSSASN1Utils.getAsn1AttributeSet(unsignedAttributesOne, id_aa_ATSHashIndex);
				ASN1Set asn1SetTwo = DSSASN1Utils.getAsn1AttributeSet(unsignedAttributesTwo, id_aa_ATSHashIndex);
				
				if (asn1SetOne != null && asn1SetTwo != null) {
					ASN1Sequence sequenceOne = (ASN1Sequence) DSSASN1Utils.getAsn1AttributeSet(unsignedAttributesOne, id_aa_ATSHashIndex).getObjectAt(0);
					int hashTableSizeOne = getHashTableSize(sequenceOne);
					
					ASN1Sequence sequenceTwo = (ASN1Sequence) DSSASN1Utils.getAsn1AttributeSet(unsignedAttributesTwo, id_aa_ATSHashIndex).getObjectAt(0);
					int hashTableSizeTwo = getHashTableSize(sequenceTwo);
					
					if (hashTableSizeOne < hashTableSizeTwo) {
						result = -1;
					} else if (hashTableSizeOne > hashTableSizeTwo) {
						result = 1;
					}
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
