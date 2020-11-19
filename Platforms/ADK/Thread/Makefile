all:	ADK
	(cd ADK/External/mdnsresponder; \
	 for file in `find . -name \*.\[ch\] -print`; do \
	     if ! cmp -s ../../../../../../$${file} $${file}; then \
                 cp ../../../../../../$${file} $${file}; \
                 echo cp ../../../../../../$${file} $${file}; \
             fi; \
	 done)
	(cd ADK; make TARGET=nRF52 PROTOCOLS=THREAD USE_STATIC_COMMISSIONING=1 USE_BLE=0 apps)

clean:
	(cd ADK; make TARGET=nRF52 PROTOCOLS=THREAD USE_STATIC_COMMISSIONING=1 USE_BLE=0 clean)

ADK:
	git clone git@github.pie.apple.com:Home-ADK/ADK.git

update:
	(cd ADK; git pull)

install:
	(cd ADK; USE_STATIC_COMMISSIONING=1 ./Tools/install.sh -d nRF52 -a Output/nRF52-arm-none-eabi-gcc/Debug/THREAD/Applications/Lightbulb.Oberon -k -t thread)
