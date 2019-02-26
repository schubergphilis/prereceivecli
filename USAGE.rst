=====
Usage
=====


To develop on prereceivecli:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scipts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scipts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use prereceivecli in a project:

At least python3.6 is required.

.. code-block:: bash

    pip install prereceivecli

    # make system directory for configuration
    sudo mkdir /etc/prereceive

    # copy over the logging.json from the project
    sudo cp /usr/local/lib/{PYTHON_VERSION_HERE}/site-packages/prereceivecli/conf/logging.json /etc/prereceive/logging.json

    # create the calling script
    cat <<EOF > /etc/prereceive/pre-receive_active
    #!/bin/sh
    SLACK_WEB_HOOK=SLACK_WEBHOOK
    AWS_SECRET=AWS_SECRET
    AWS_KEY=AWS_KEY
    AWS_REGION=eu-west-1

    /usr/local/bin/pre-receive -l /etc/prereceive/logging.json \
                               -w "${SLACK_WEB_HOOK}" \
                               -s "${AWS_SECRET}" \
                               -k "${AWS_KEY}"  \
                               -r "${AWS_REGION}" \
                               --no-aggressive-check
    EOF

    # give access to git user to the directory
    sudo chown -R git.git /etc/prereceive

    # setup logging directory and give appropriate permissions
    sudo mkdir /var/log/prereceive
    sudo chown git.git /var/log/prereceive

    # create the actuall git hook script by linking to the appropriate directory.
    # if the location is wrong for you please consult the appropriate documentation for your installation.
    sudo mkdir -p /opt/gitlab/embedded/service/gitlab-shell/hooks/pre-receive.d
    sudo ln -s /etc/prereceive/pre-receive_active /opt/gitlab/embedded/service/gitlab-shell/hooks/pre-receive.d/pre-receive_active
