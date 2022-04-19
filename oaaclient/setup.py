from setuptools import setup, find_packages

setup(name='oaaclient',
      version='0.2',
      description='Veza OAA SDK',
      author='Jim Lester',
      author_email='jim.lester@veza.com',
      include_package_data=True,
      zip_safe=False,
      packages=['oaaclient'],
      package_dir = {'oaaclient': 'src'}
      )
