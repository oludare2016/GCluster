from django.core.exceptions import ValidationError


def validate_file_size(image):
    """
    Validate the size of an image file.

    Args:
        image (File): The image file to validate.

    Raises:
        ValidationError: If the size of the image file exceeds the maximum allowed size.

    """
    max_size = 10 * 1024 * 1024  # 10 MB
    if image.size > max_size:
        raise ValidationError(f"File too large ( > {max_size} bytes )")
