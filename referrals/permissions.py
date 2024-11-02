from rest_framework.permissions import BasePermission


class IsCompanyOrAdmin(BasePermission):
    """
    Custom permission to only allow companies or admins to create and edit products.
    """

    def has_permission(self, request, view):
        return request.user.user_type in ["company", "admin"]

    def has_object_permission(self, request, view, obj):
        # Admins can do anything
        if request.user.user_type == "admin":
            return True

        # Company users can only edit their own products
        if request.user.user_type == "company" and obj.company == request.user:
            return True

        return False


class IsAdmin(BasePermission):
    """
    Custom permission to only allow admins to approve or disapprove products.
    """

    def has_permission(self, request, view):
        return request.user.user_type == "admin"

    def has_object_permission(self, request, view, obj):
        return request.user.user_type == "admin"


class IsOwnerOrAdmin(BasePermission):
    """
    Custom permission to only allow owners of a product or admins to view or edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Admins can do anything
        if request.user.user_type == "admin":
            return True

        # Company users can only view or edit their own products
        if request.user.user_type == "company" and obj.company == request.user:
            return True

        return False


class CanApproveOrDisapprove(BasePermission):
    """
    Custom permission to only allow admins to approve or disapprove products.
    """

    def has_object_permission(self, request, view, obj):
        # Only admins can approve or disapprove
        return request.user.user_type == "admin"
