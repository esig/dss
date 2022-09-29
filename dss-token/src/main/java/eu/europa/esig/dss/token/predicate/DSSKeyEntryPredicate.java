package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.function.Predicate;

/**
 * This predicate allows filtering of {@code DSSPrivateKeyEntry} within a {@code SignatureTokenConnection}
 * (see {@code AbstractKeyStoreTokenConnection#getKeys}).
 *
 */
public interface DSSKeyEntryPredicate extends Predicate<DSSPrivateKeyEntry> {

}
