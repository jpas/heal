{
  description = "A very basic flake";

  inputs = {
    nixpkgs-he.url = "github:jpas/nixpkgs-he";
    nixpkgs.follows = "nixpkgs-he/nixpkgs";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, nixpkgs-he, flake-compat } @ inputs:
    let
      supportedSystems = [ "x86_64-linux" ];

      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system);

      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ self.overlay nixpkgs-he.overlay ];
      };

      version = "${self.lastModifiedDate}.${self.shortRev or "dirty"}";
    in
    {
      overlay = final: prev: {
        heal = with final; stdenv.mkDerivation {
          name = "heal-${version}";

          src = ./.;

          nativeBuildInputs = [ cmake ];
          buildInputs = [ seal ];
        };
      };

      defaultPackage = forAllSystems (system: (pkgsFor system).heal);
    };
}
