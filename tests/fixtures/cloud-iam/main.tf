resource "aws_iam_role" "deployer" {
  name = "deployer"
}

resource "aws_iam_policy" "assume" {
  policy = jsonencode({ Action = ["sts:AssumeRole"] })
}
