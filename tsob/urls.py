from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from tsob import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('symmetrickey/', views.create_new_symmetric_key),
    path('privatekey/', views.create_new_private_key),
    path('reencrypt/', views.re_encrypt_private_keys),
    path('sign/', views.sign_badges),
    path('deepvalidate/', views.deep_validate),
]

if settings.DEBUG:
    import debug_toolbar

    urlpatterns += [path('__debug__/', include(debug_toolbar.urls))]
