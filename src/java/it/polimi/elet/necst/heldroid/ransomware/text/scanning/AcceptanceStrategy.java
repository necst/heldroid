package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import it.polimi.elet.necst.heldroid.ransomware.text.FileClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;

public abstract class AcceptanceStrategy {
	public abstract Result accepts(TextClassification textClassification);

	public static Result fail() {
		Result result = new Result();
		result.setAccepted(false);
		result.setScore(0);
		return result;
	}

	public static Result fail(double score) {
		Result result = fail();
		result.setScore(score);
		return result;
	}

	public static Result fail(String comment) {
		Result result = fail();
		result.setComment(comment);
		return result;
	}

	public static class Result {
		private boolean accepted;
		private double score;
		public String comment;
		public FileClassification fileClassification;

		public boolean isAccepted() {
			return accepted;
		}

		public void setAccepted(boolean accepted) {
			this.accepted = accepted;
		}

		public double getScore() {
			return score;
		}

		public void setScore(double score) {
			this.score = score;
		}

		public String getComment() {
			return comment;
		}

		public void setComment(String comment) {
			this.comment = comment;
		}

		public FileClassification getFileClassification() {
			return fileClassification;
		}
		
		public void setFileClassification(
				FileClassification fileClassification) {
			this.fileClassification = fileClassification;
		}
	}
}
