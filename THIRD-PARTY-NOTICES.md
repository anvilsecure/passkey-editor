# Third-party notices

Passkey Editor is released under the [MIT License](LICENSE). The extension is distributed as a single
self-contained jar, which bundles the third-party components listed below. Each remains under its own
license, reproduced with the component.

## Bundled in the extension jar

| Component | Version | License |
| --- | --- | --- |
| [webauthn4j-core](https://github.com/webauthn4j/webauthn4j) | 0.28.3.RELEASE | Apache License 2.0 |
| [webauthn4j-util](https://github.com/webauthn4j/webauthn4j) | 0.28.3.RELEASE | Apache License 2.0 |
| [jackson-databind](https://github.com/FasterXML/jackson-databind) | 2.18.2 | Apache License 2.0 |
| [jackson-core](https://github.com/FasterXML/jackson-core) | 2.18.2 | Apache License 2.0 |
| [jackson-annotations](https://github.com/FasterXML/jackson-annotations) | 2.18.2 | Apache License 2.0 |
| [jackson-dataformat-cbor](https://github.com/FasterXML/jackson-dataformats-binary) | 2.18.2 | Apache License 2.0 |
| [FastDoubleParser](https://github.com/wrandelshofer/FastDoubleParser) | bundled inside jackson-core 2.18.2 | MIT License; its big-integer parsing code is additionally covered by the BSD 2-Clause License |
| [gson](https://github.com/google/gson) | 2.14.0 | Apache License 2.0 |
| [error_prone_annotations](https://github.com/google/error-prone) | 2.48.0 | Apache License 2.0 |
| [slf4j-api](https://github.com/qos-ch/slf4j) | 2.0.16 | MIT License |

Full license texts: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0),
[MIT License](https://opensource.org/license/mit).

The jar carries each component's own notice files under `META-INF/`. The four Jackson artifacts ship a
`META-INF/NOTICE` that is the same copyright and licensing statement in each, so the jar keeps a single
copy; every notice with distinct content (`FastDoubleParser-NOTICE`, `FastDoubleParser-LICENSE`,
`thirdparty-LICENSE`) has its own name and is preserved.

## Not bundled

The Burp Montoya API (`net.portswigger.burp.extensions:montoya-api`) is a **compile-only** dependency,
provided by Burp Suite at runtime. It is not open source and is not redistributed with this extension:
no Montoya class is present in the built jar.
