from django.urls import path

from netbox_passwork import views

urlpatterns = [
    # Auth
    path("auth/login/", views.PassworkLoginView.as_view(), name="pw_auth_login"),
    path("auth/totp/", views.PassworkTotpView.as_view(), name="pw_auth_totp"),
    # Secrets
    path("secrets/", views.SecretsListView.as_view(), name="pw_secrets_list"),
    path("secrets/<str:pw_id>/detail/", views.SecretDetailView.as_view(), name="pw_secret_detail"),
    path("secrets/<str:pw_id>/copy/", views.SecretCopyView.as_view(), name="pw_secret_copy"),
    # Bindings
    path("bindings/", views.BindingsCreateView.as_view(), name="pw_bindings_create"),
    path("bindings/<int:binding_id>/", views.BindingsDeleteView.as_view(), name="pw_bindings_delete"),
    # Picker
    path("picker/folders/", views.PickerFoldersView.as_view(), name="pw_picker_folders"),
    path(
        "picker/folders/<str:vault_id>/items/",
        views.PickerFolderContentsView.as_view(),
        name="pw_picker_folder_items",
    ),
    path("picker/search/", views.PickerSearchView.as_view(), name="pw_picker_search"),
    # Audit
    path("audit/", views.AuditLogView.as_view(), name="pw_audit"),
]
