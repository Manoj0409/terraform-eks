resource "aws_vpc" "vpc1" {
  cidr_block           = var.vpc-cidr
  instance_tenancy     = "default"
  enable_dns_hostnames = "true"
  tags = {
    Name = "my-vpc-1"
  }
}

resource "aws_security_group" "Sec1" {
  name        = "Sec-1"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.vpc1.id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "Sec-1"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = "my-igw1"
  }
}

resource "aws_route_table" "test" {
  vpc_id = aws_vpc.vpc1.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "RT-1"
  }
}

resource "aws_subnet" "Subnet1" {
  count                   = length(var.subnet-cidr)
  availability_zone       = element(var.availability-zone, count.index)
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = element(var.subnet-cidr, count.index)
  map_public_ip_on_launch = "true"
  tags = {
    Name = "Subnet-${count.index + 1}"
  }
}

resource "aws_route_table_association" "a" {
  count          = length(var.subnet-cidr)
  subnet_id      = aws_subnet.Subnet1[count.index].id
  route_table_id = aws_route_table.test.id
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "iam-role" {
  name               = "eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.iam-role.id
}

resource "aws_eks_cluster" "example" {
  name     = "EKS-cluster"
  role_arn = aws_iam_role.iam-role.arn

  vpc_config {
    subnet_ids = [aws_subnet.Subnet1[0].id, aws_subnet.Subnet1[1].id, ]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
  ]
}

resource "aws_iam_role" "example" {
  name = "eks-node-group-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.example.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.example.name
}

resource "aws_iam_role_policy_attachment" "example-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.example.name
}

resource "aws_eks_node_group" "example" {
  cluster_name    = aws_eks_cluster.example.name
  node_group_name = "EKS-nodegroup"
  node_role_arn   = aws_iam_role.example.arn
  subnet_ids      = [aws_subnet.Subnet1[0].id, aws_subnet.Subnet1[1].id, ]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    role = "general"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly,
  ]
}

data "tls_certificate" "eks" {
  url = aws_eks_cluster.example.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.example.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
}

data "aws_iam_policy_document" "test" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:default:aws-test"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "test_oidc" {
  assume_role_policy = data.aws_iam_policy_document.test.json
  name               = "test-oidc"
}

resource "aws_iam_policy" "test-policy" {
  name = "test-policy"
  policy = jsonencode ({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "*",
      ]
      Effect   = "Allow"
      Resource = "arn:aws:s3:::*"
    },
    ]
  })
}


resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test_oidc.name
  policy_arn = aws_iam_policy.test-policy.arn
}
# Create the EKS cluster
/*module "eks_cluster" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "EKS-cluster"
  cluster_version = "1.21"
  subnets         = [aws_subnet.Subnet1[0].id, aws_subnet.Subnet1[1].id, ]
  vpc_id          = aws_vpc.vpc1.id
}

# Create the EKS node group
module "eks_node_group" {
  source                      = "terraform-aws-modules/eks/aws//modules/node_group"
  cluster_name                = module.eks_cluster.cluster_id
  node_group_name             = "my-nodegroup"
  node_group_desired_capacity = 2
  node_group_min_size         = 1
  node_group_max_size         = 3
  node_group_instance_type    = "t2.micro"
  subnets                     = [aws_subnet.Subnet1[0].id, aws_subnet.Subnet1[1].id]
  node_group_key_name         = "DevOps"
}
*/




