package it.polimi.elet.necst.heldroid.ransomware.text.classification;

public class SentenceClassification {
    private String category, text;
    private double likelihood;
    private int producedStemsCount;

    public String getCategory() {
        return category;
    }

    void setCategory(String category) {
        this.category = category;
    }

    public double getLikelihood() {
        return likelihood;
    }

    void setLikelihood(double likelihood) {
        this.likelihood = likelihood;
    }

    public String getText() {
        return text;
    }

    void setText(String text) {
        this.text = text;
    }

    public boolean isValid() {
        return (this.likelihood > 0);
    }

    public int getProducedStemsCount() {
        return producedStemsCount;
    }

    void setProducedStemsCount(int producedStemsCount) {
        this.producedStemsCount = producedStemsCount;
    }

    @Override
    public String toString() {
        return String.format("[%s: %2f] %s", this.category, this.likelihood, this.text);
    }
}
