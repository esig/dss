package eu.europa.esig.dss.model;

/**
 * Defines limits of transactions for a given certificate (QcStatement)
 */
public class QCLimitValue {

    /** The used currency */
    private String currency;

    /** The transaction amount */
    private int amount;

    /** The exponent */
    private int exponent;

    /**
     * Gets the currency
     *
     * @return {@link String}
     */
    public String getCurrency() {
        return currency;
    }

    /**
     * Sets the currency
     *
     * @param currency {@link String}
     */
    public void setCurrency(String currency) {
        this.currency = currency;
    }

    /**
     * Gets the amount
     *
     * @return integer
     */
    public int getAmount() {
        return amount;
    }

    /**
     * Sets the amount
     *
     * @param amount integer
     */
    public void setAmount(int amount) {
        this.amount = amount;
    }

    /**
     * Gets the exponent
     *
     * @return integer
     */
    public int getExponent() {
        return exponent;
    }

    /**
     * Sets the exponent
     *
     * @param exponent integer
     */
    public void setExponent(int exponent) {
        this.exponent = exponent;
    }

}
