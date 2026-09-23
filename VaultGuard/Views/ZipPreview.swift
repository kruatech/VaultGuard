import SwiftUI

// The archive reader and tree model live in `Services/ZipListing.swift`, where the unit tests can
// reach them.

// MARK: - UI

struct ZipPreviewView: View {
    let data: Data

    private enum Listing {
        case loading
        case ready([ZipNode])
        case unreadable
    }

    @State private var listing: Listing = .loading

    var body: some View {
        Group {
            switch listing {
            case .loading:
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            case .ready(let nodes):
                List {
                    OutlineGroup(nodes, children: \.children) { node in
                        HStack(spacing: 8) {
                            Image(systemName: node.isDirectory ? "folder.fill" : "doc")
                                .font(VGFont.body)
                                .foregroundColor(node.isDirectory ? .accentColor : .secondary)
                                .vgDecorative()
                            Text(node.name).font(VGFont.label)
                        }
                    }
                }
                .listStyle(.sidebar)
            case .unreadable:
                VStack(spacing: 10) {
                    Image(systemName: "doc.zipper").font(.system(size: 48, weight: .ultraLight))
                        .foregroundColor(.secondary).vgDecorative()
                    Text(L10n.Misc.cannotOpenFile.localized).font(VGFont.bodyLarge).foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        // Parsed once, off the main thread, and kept.
        //
        // This used to be a computed property, re-evaluated on every render: the whole archive was
        // copied and re-parsed each time SwiftUI redrew, and each parse minted fresh node ids, so
        // the outline collapsed back to its top level whenever anything on screen changed. With
        // attachments up to 100 MB the copy alone was a visible stall.
        .task {
            let payload = data
            let nodes = await Task.detached(priority: .userInitiated) { () -> [ZipNode]? in
                guard let paths = ZipDirectoryReader.entryPaths(from: payload) else { return nil }
                return ZipNode.buildTree(from: paths)
            }.value
            if let nodes, !nodes.isEmpty { listing = .ready(nodes) } else { listing = .unreadable }
        }
    }
}
